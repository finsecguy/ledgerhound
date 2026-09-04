"""Domain registration data: RDAP primary, real WHOIS fallback.

RDAP (RFC 7480+) is ICANN-mandated for gTLD registries and is plain
HTTPS/JSON — it's the primary source here. But RDAP deployment is not
universal: several ccTLDs (`.sk`, `.ch`, and others verified live during
development) either have no RDAP server registered in IANA's bootstrap
registry at all, or an incomplete/unreliable one (`.cz` has a bootstrap
entry but its RDAP server isn't consistently reliable). For those,
falling back to nothing would silently lose registration data for a
meaningful slice of ccTLD-hosted phishing domains — so this module also
implements classic port-43 WHOIS as an explicit fallback, not a
convenience.

Two RDAP providers (IANA-bootstrap-resolved, then rdap.org as an
independent second RDAP path) plus one WHOIS provider, in that order, all
in the `domain_rdap` facet chain. All three write the same
`DomainRegistrationProfile` shape into `domain_profiles`; the serving
provider is recorded on that row like every other enrichment.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import (
    EnrichmentTarget,
    Provider,
    ProviderError,
    ProviderResult,
    RateLimit,
)

logger = structlog.get_logger(__name__)


class DomainRegistrationProfile(BaseModel):
    """Normalized registration data, produced by either RDAP or WHOIS."""

    #: False only once a provider has positively confirmed the domain is
    #: unregistered (RDAP 404 / WHOIS "not found" text) — a real result,
    #: not a failure.
    registered: bool = True
    registrar: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    expires_at: datetime | None = None
    registrant_country: str | None = None
    #: True if registrant details appear to be privacy-redacted rather
    #: than genuinely absent. Redaction status is itself a weak signal
    #: (redacted-by-default is near-universal for gTLDs post-2018) and is
    #: always stored, never treated as "no data."
    redacted: bool = False
    status: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)


# --- RDAP JSON parsing -------------------------------------------------

_REDACTED_VALUE_MARKERS = {
    "redacted for privacy",
    "data protected",
    "not disclosed",
    "redacted",
    "gdpr redacted",
    "personal data withheld",
}


def _entity_fn(entity: dict[str, Any]) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            value = item[3]
            return str(value) if value else None
    return None


def _entity_country(entity: dict[str, Any]) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
            adr = item[3]
            if isinstance(adr, list) and len(adr) >= 7 and adr[6]:
                return str(adr[6])
    return None


def _is_redacted_marker(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _REDACTED_VALUE_MARKERS


def _has_rfc9537_redaction(payload: dict[str, Any]) -> bool:
    """RFC 9537 "Redaction of Personal Data in EPP and RDAP": a top-level
    `redacted` array of {name, prePath, method, reason} entries. Presence
    of any entry is itself the authoritative redaction signal — it's a
    structured declaration, not a heuristic."""
    redacted = payload.get("redacted")
    return isinstance(redacted, list) and len(redacted) > 0


def _has_redaction_remark(payload: dict[str, Any]) -> bool:
    """Some registries signal redaction via a top-level remark with an
    empty description and a title like "REDACTED FOR PRIVACY", rather
    than putting the marker inside the registrant vCard."""
    for remark in payload.get("remarks", []):
        title = str(remark.get("title", "")).lower()
        if "redact" in title:
            return True
    return False


def parse_rdap(payload: dict[str, Any]) -> DomainRegistrationProfile:
    registrar: str | None = None
    registrant_country: str | None = None
    registrant_name: str | None = None
    registrant_entity_present = False

    for entity in payload.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles and registrar is None:
            registrar = _entity_fn(entity)
        if "registrant" in roles:
            registrant_entity_present = True
            registrant_country = _entity_country(entity)
            registrant_name = _entity_fn(entity)

    created_at: datetime | None = None
    updated_at: datetime | None = None
    expires_at: datetime | None = None
    for event in payload.get("events", []):
        action = event.get("eventAction")
        date_str = event.get("eventDate")
        if not date_str:
            continue
        try:
            parsed = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            continue
        if action == "registration":
            created_at = parsed
        elif action == "expiration":
            expires_at = parsed
        elif action == "last changed":
            updated_at = parsed

    nameservers = [
        str(ns["ldhName"]) for ns in payload.get("nameservers", []) if ns.get("ldhName")
    ]

    # Missing registrant entity, an RFC 9537 declaration, a redaction
    # remark, or a known placeholder value in the vCard: any one of these
    # is sufficient to call it redacted. Order doesn't matter — they're
    # not mutually exclusive, and the result is stored either way.
    redacted = (
        not registrant_entity_present
        or _has_rfc9537_redaction(payload)
        or _has_redaction_remark(payload)
        or _is_redacted_marker(registrant_name)
        or _is_redacted_marker(registrant_country)
    )

    return DomainRegistrationProfile(
        registered=True,
        registrar=registrar,
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
        registrant_country=None if _is_redacted_marker(registrant_country) else registrant_country,
        redacted=redacted,
        status=list(payload.get("status", [])),
        nameservers=nameservers,
    )


#: rdap.org answers with a 404 for two very different situations, and
#: only its response body tells them apart: a genuine "this domain isn't
#: registered" (from the registry, usually an empty body) versus "I don't
#: have any RDAP server to ask for this TLD at all" (its own bootstrap
#: miss, body carries this exact title) — verified live against .ch/.sk.
#: The second case must NOT be recorded as `registered=False`; it must
#: fall through to the next provider (WHOIS), same as a bootstrap miss in
#: `IanaBootstrapRdapProvider` does.
_NO_RDAP_SERVICE_MARKERS = ("no rdap service", "no rdap server")


def _is_no_rdap_service_response(response: httpx.Response) -> bool:
    try:
        body = response.json()
    except ValueError:
        return False
    title = str(body.get("title", "")).lower()
    return any(marker in title for marker in _NO_RDAP_SERVICE_MARKERS)


async def _fetch_rdap(
    provider: Provider, url: str, **request_kwargs: Any
) -> ProviderResult[DomainRegistrationProfile]:
    """Shared by both RDAP providers: fetch + parse, with 404 (domain not
    registered) treated as a valid result rather than a failure. 429 is
    not special-cased here — it's already in `http_request`'s retryable
    set, so backoff happens transparently before this ever sees it."""
    try:
        response = await provider.request("GET", url, **request_kwargs)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            if _is_no_rdap_service_response(exc.response):
                raise ProviderError(
                    f"{provider.name}: no RDAP service available for this TLD"
                ) from exc
            return ProviderResult(
                provider=provider.name,
                raw={"status_code": 404, "url": url},
                normalized=DomainRegistrationProfile(registered=False),
                fetched_at=datetime.now(UTC),
            )
        raise
    payload = response.json()
    return ProviderResult(
        provider=provider.name,
        raw=payload,
        normalized=parse_rdap(payload),
        fetched_at=datetime.now(UTC),
    )


DEFAULT_BOOTSTRAP_CACHE_PATH = Path(".cache/rdap_bootstrap.json")


class IanaBootstrapRdapProvider(Provider):
    """Primary: resolve the authoritative RDAP server for a domain's TLD
    via IANA's own bootstrap registry, then query it directly. Never
    hardcodes a per-TLD server — the bootstrap file is the single source
    of truth for "who answers RDAP for this TLD," fetched fresh at most
    once per `bootstrap_ttl` and cached to disk so a run doesn't refetch
    the (small, but non-trivial) file per domain.
    """

    name = "rdap_iana"
    supports = {IndicatorType.DOMAIN}
    rate_limit = RateLimit(max_requests=5, per_seconds=10)
    ttl = timedelta(hours=48)

    bootstrap_url = "https://data.iana.org/rdap/dns.json"
    bootstrap_ttl = timedelta(hours=24)

    def __init__(self, *, cache_path: Path = DEFAULT_BOOTSTRAP_CACHE_PATH, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.cache_path = cache_path
        self._bootstrap_cache: dict[str, list[str]] | None = None

    def _cache_is_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        mtime = datetime.fromtimestamp(self.cache_path.stat().st_mtime, tz=UTC)
        return datetime.now(UTC) - mtime < self.bootstrap_ttl

    async def _load_bootstrap(self) -> dict[str, list[str]]:
        if self._bootstrap_cache is not None:
            return self._bootstrap_cache

        if self._cache_is_fresh():
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        else:
            response = await self.request("GET", self.bootstrap_url)
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(response.text, encoding="utf-8")
            payload = response.json()

        mapping: dict[str, list[str]] = {}
        for tlds, urls in payload.get("services", []):
            for tld in tlds:
                mapping[tld.lower()] = list(urls)
        self._bootstrap_cache = mapping
        return mapping

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[DomainRegistrationProfile]:
        domain = target.value
        tld = domain.rsplit(".", 1)[-1].lower()
        bootstrap = await self._load_bootstrap()
        base_urls = bootstrap.get(tld)
        if not base_urls:
            raise ProviderError(f"no RDAP server registered for TLD {tld!r}")

        base = base_urls[0].rstrip("/")
        return await _fetch_rdap(self, f"{base}/domain/{domain}")


class RdapOrgProvider(Provider):
    """Secondary RDAP path: rdap.org does its own bootstrap resolution and
    redirects to the right authoritative server, independent of our own
    bootstrap file/cache/logic — a genuinely separate failure domain from
    `IanaBootstrapRdapProvider`, not just a second implementation of the
    same lookup."""

    name = "rdap_org"
    supports = {IndicatorType.DOMAIN}
    rate_limit = RateLimit(max_requests=5, per_seconds=10)
    ttl = timedelta(hours=48)

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[DomainRegistrationProfile]:
        domain = target.value
        return await _fetch_rdap(
            self, f"https://rdap.org/domain/{domain}", follow_redirects=True
        )


# --- WHOIS (port 43) fallback -----------------------------------------

IANA_WHOIS_HOST = "whois.iana.org"
WHOIS_PORT = 43
_SOCKET_TIMEOUT = 10.0

#: A handful of registries require a command prefix rather than a bare
#: domain name. SK-NIC is the concrete, verified-live example; add more
#: here as they're discovered rather than assuming bare-domain works
#: universally (thin-gTLD-style referral chasing, e.g. Verisign's
#: registrar-WHOIS-server hop for .com, is out of scope — WHOIS is only
#: ever reached here for TLDs RDAP doesn't cover, which in practice means
#: ccTLDs with thick, direct-answer registries, not gTLDs).
_QUERY_FORMATS: dict[str, str] = {
    "sk": "domain {domain}",
}

_NOT_FOUND_MARKERS = (
    "domain not found",
    "no match for",
    "not found",
    "no entries found",
    "no data found",
    "object does not exist",
)


def _looks_like_not_found(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _NOT_FOUND_MARKERS)


async def _whois_query(host: str, query: str, *, timeout: float = _SOCKET_TIMEOUT) -> str:
    """Raw port-43 WHOIS query, behind the same retry/backoff shape as
    every HTTP call in this codebase (tenacity, exponential backoff, a
    few attempts) — it just can't literally be `http_request`, since this
    isn't HTTP. See `infra/dns.py` for the same reasoning applied to
    dnspython's UDP/TCP resolver."""

    async def _do_query() -> str:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, WHOIS_PORT), timeout=timeout
        )
        try:
            writer.write((query + "\r\n").encode("ascii", errors="ignore"))
            await writer.drain()
            chunks: list[bytes] = []
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", errors="replace")
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async for attempt in AsyncRetrying(
        retry=retry_if_exception_type((OSError, TimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1.0),
        reraise=True,
    ):
        with attempt:
            return await _do_query()
    raise AssertionError("unreachable: AsyncRetrying always raises or returns")


async def _resolve_whois_server(
    tld: str, *, cache: dict[str, str | None], timeout: float = _SOCKET_TIMEOUT
) -> str | None:
    """Per-TLD WHOIS server, resolved via IANA's own referral rather than
    a hardcoded map — query `whois.iana.org` for the TLD and read the
    `whois:`/`refer:` field out of its response."""
    if tld in cache:
        return cache[tld]
    try:
        raw = await _whois_query(IANA_WHOIS_HOST, tld, timeout=timeout)
    except (OSError, TimeoutError):
        cache[tld] = None
        return None

    server: str | None = None
    for line in raw.splitlines():
        lowered = line.lower()
        if lowered.startswith(("whois:", "refer:")):
            server = line.split(":", 1)[1].strip()
            break
    cache[tld] = server
    return server


@dataclass(frozen=True, slots=True)
class _WhoisParseResult:
    profile: DomainRegistrationProfile
    complete: bool


def _parse_date_generic(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
        try:
            parsed = datetime.strptime(candidate, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _parse_generic_whois(text: str) -> _WhoisParseResult:
    """Best-effort parser for whatever registry format shows up: tries
    several common field-label variants across real-world WHOIS output.
    There is no universal WHOIS schema, so this will not extract
    everything for every registry — `complete` reflects that."""
    field_patterns = {
        "registrar": r"(?im)^(?:registrar|sponsoring registrar)\s*:\s*(.+)$",
        "created_at": (
            r"(?im)^(?:creation date|created|domain registration date|registered on)"
            r"\s*:\s*(.+)$"
        ),
        "expires_at": (
            r"(?im)^(?:registry expiry date|expiry date|expiration date|paid-till|"
            r"valid until)\s*:\s*(.+)$"
        ),
        "updated_at": r"(?im)^(?:updated date|updated|last modified|changed)\s*:\s*(.+)$",
        "registrant_country": r"(?im)^(?:registrant country|country|country code)\s*:\s*(\S+)$",
    }
    fields: dict[str, str] = {}
    for key, pattern in field_patterns.items():
        match = re.search(pattern, text)
        if match:
            fields[key] = match.group(1).strip()

    nameservers = re.findall(
        r"(?im)^(?:name server|nserver|domain nameserver|nameserver)\s*:\s*(\S+)", text
    )
    statuses: list[str] = []
    for match in re.finditer(r"(?im)^(?:domain status|status)\s*:\s*(.+)$", text):
        statuses.extend(part.strip() for part in match.group(1).split(",") if part.strip())

    lowered = text.lower()
    redacted = "redact" in lowered or "privacy" in lowered or "not disclosed" in lowered

    profile = DomainRegistrationProfile(
        registered=True,
        registrar=fields.get("registrar"),
        created_at=_parse_date_generic(fields.get("created_at")),
        updated_at=_parse_date_generic(fields.get("updated_at")),
        expires_at=_parse_date_generic(fields.get("expires_at")),
        registrant_country=fields.get("registrant_country"),
        redacted=redacted,
        status=statuses,
        nameservers=nameservers,
    )
    complete = bool(
        profile.registrar and (profile.created_at or profile.expires_at) and profile.nameservers
    )
    return _WhoisParseResult(profile=profile, complete=complete)


def _parse_sk_whois(text: str) -> _WhoisParseResult:
    """SK-NIC's format, verified against the live registry. Its "Created:"
    label appears twice — once for the domain, once (further down) for
    the registrant contact — `re.search` takes the first match, which is
    the domain's, since it appears first in the response."""

    def field(label: str) -> str | None:
        match = re.search(rf"(?im)^{re.escape(label)}\s*:\s*(.+)$", text)
        return match.group(1).strip() if match else None

    created = _parse_date_generic(field("Created"))
    updated = _parse_date_generic(field("Updated"))
    expires = _parse_date_generic(field("Valid Until"))
    registrar = field("Authorised Registrar")
    status_line = field("Domain Status") or ""
    statuses = [part.strip() for part in status_line.split(",") if part.strip()]
    nameservers = re.findall(r"(?im)^Nameserver\s*:\s*(\S+)", text)
    country = field("Country Code")

    profile = DomainRegistrationProfile(
        registered=True,
        registrar=registrar,
        created_at=created,
        updated_at=updated,
        expires_at=expires,
        registrant_country=country,
        redacted=False,  # SK-NIC publishes registrant data directly, unredacted
        status=statuses,
        nameservers=nameservers,
    )
    complete = bool(registrar and created and nameservers)
    return _WhoisParseResult(profile=profile, complete=complete)


_PARSERS: dict[str, Callable[[str], _WhoisParseResult]] = {
    "sk": _parse_sk_whois,
}


class WhoisProvider(Provider):
    """Fallback of last resort: used only when the bootstrap registry has
    no RDAP server for a TLD, or both RDAP providers in the chain fail.
    Per-TLD WHOIS server resolved via IANA's referral, parsed with a
    per-TLD parser where one exists (`.sk`, verified live) and a generic
    best-effort parser otherwise. WHOIS has no machine-readable schema
    across registries, so a result here is frequently `partial=True`.
    """

    name = "whois"
    supports = {IndicatorType.DOMAIN}
    rate_limit = RateLimit(max_requests=5, per_seconds=10)
    ttl = timedelta(hours=48)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._server_cache: dict[str, str | None] = {}

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[DomainRegistrationProfile]:
        domain = target.value
        tld = domain.rsplit(".", 1)[-1].lower()

        server = await _resolve_whois_server(tld, cache=self._server_cache)
        if not server:
            raise ProviderError(f"no WHOIS server referral found for TLD {tld!r}")

        query = _QUERY_FORMATS.get(tld, "{domain}").format(domain=domain)
        raw_text = await _whois_query(server, query)

        if _looks_like_not_found(raw_text):
            return ProviderResult(
                provider=self.name,
                raw={"text": raw_text, "server": server},
                normalized=DomainRegistrationProfile(registered=False),
                fetched_at=datetime.now(UTC),
            )

        parser = _PARSERS.get(tld, _parse_generic_whois)
        parsed = parser(raw_text)
        return ProviderResult(
            provider=self.name,
            raw={"text": raw_text, "server": server},
            normalized=parsed.profile,
            fetched_at=datetime.now(UTC),
            partial=not parsed.complete,
        )
