"""HTTP response fingerprinting: what does this domain actually serve?

Not really a "provider" in the multi-source sense. There's only one
source for "what does this website respond with," which is the website
itself. A connection failure, TLS error, or non-2xx status is a valid
*result*, not an exception to bubble up: a scam domain going dark, or a
phishing kit disappearing after takedown, is itself intelligence. Only a
genuinely unexpected error (a bug, not "the site is down") should ever
surface as a `ProviderError`.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta

import httpx
from pydantic import BaseModel

from ledgerhound.assess.untrusted import neutralize_untrusted_text
from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget, Provider, ProviderResult, RateLimit

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class HttpFingerprint(BaseModel):
    reachable: bool
    status: int | None = None
    server_header: str | None = None
    title: str | None = None
    body_hash: str | None = None
    favicon_hash: str | None = None
    #: e.g. "connection_error", "timeout", "tls_error". Populated only
    #: when `reachable` is False, for why, not treated as a failure.
    unreachable_reason: str | None = None


class HttpFingerprintProvider(Provider):
    name = "http_fingerprint"
    supports = {IndicatorType.DOMAIN}
    rate_limit = RateLimit(max_requests=10, per_seconds=10)
    ttl = timedelta(hours=6)

    async def _fetch(self, url: str) -> httpx.Response:
        # Deliberately not going through the shared retry wrapper: a dead
        # or parked domain not responding IS the result we want to record,
        # not a transient error worth retrying three times with backoff.
        return await self.client.get(url, follow_redirects=True, timeout=10.0)

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[HttpFingerprint]:
        domain = target.value
        last_reason = "unknown_error"
        for scheme in ("https", "http"):
            try:
                response = await self._fetch(f"{scheme}://{domain}/")
            except httpx.TimeoutException:
                last_reason = "timeout"
                continue
            except httpx.ConnectError:
                last_reason = "connection_error"
                continue
            except httpx.TransportError as exc:
                last_reason = f"tls_error: {exc}" if "ssl" in str(exc).lower() else str(exc)
                continue

            body = response.content
            title_match = _TITLE_RE.search(body)
            raw_title = (
                title_match.group(1).decode("utf-8", errors="replace").strip()
                if title_match
                else ""
            )
            # Titles are attacker-controlled. Strip instruction-shaped text
            # before the fingerprint is stored.
            title = neutralize_untrusted_text(raw_title)[:500] if raw_title else None
            favicon_hash = await self._favicon_hash(f"{scheme}://{domain}")

            fingerprint = HttpFingerprint(
                reachable=True,
                status=response.status_code,
                server_header=response.headers.get("server"),
                title=title[:500] if title else None,
                body_hash=hashlib.sha256(body).hexdigest(),
                favicon_hash=favicon_hash,
            )
            return ProviderResult(
                provider=self.name,
                raw={
                    "scheme": scheme,
                    "status": response.status_code,
                    "headers": dict(response.headers),
                },
                normalized=fingerprint,
                fetched_at=datetime.now(UTC),
            )

        fingerprint = HttpFingerprint(reachable=False, unreachable_reason=last_reason)
        return ProviderResult(
            provider=self.name,
            raw={"unreachable_reason": last_reason},
            normalized=fingerprint,
            fetched_at=datetime.now(UTC),
        )

    async def _favicon_hash(self, origin: str) -> str | None:
        try:
            response = await self.client.get(f"{origin}/favicon.ico", timeout=5.0)
        except httpx.TransportError:
            return None
        if response.status_code != 200 or not response.content:
            return None
        return hashlib.sha256(response.content).hexdigest()

