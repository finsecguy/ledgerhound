"""Certificate transparency lookups via crt.sh.

crt.sh is the one facet here with a single provider rather than a
fallback pair: it's the only free, comprehensive, queryable aggregator
over the public CT logs. A second CT-log source would mean either paying
for one or implementing the raw CT log protocol directly (fetching and
verifying signed tree heads from each log operator). Out of scope for
what this facet needs. Domain enrichment as a whole still has redundancy
across its four independent facets (DNS, RDAP, certs, HTTP); losing this
one facet doesn't take down domain enrichment entirely.

crt.sh's shared, community-funded infrastructure is also easy to
overload, which is why this provider's configured rate limit
(`config/providers.yaml`) is the most conservative of any provider in
the codebase.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import (
    EnrichmentTarget,
    Provider,
    ProviderError,
    ProviderResult,
    RateLimit,
)


class CertObservation(BaseModel):
    san: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial_number: str


class CertHistory(BaseModel):
    certs: list[CertObservation] = Field(default_factory=list)


def _parse_crtsh(entries: list[dict[str, Any]]) -> CertHistory:
    seen: set[tuple[str, str]] = set()
    certs: list[CertObservation] = []
    for entry in entries:
        serial = str(entry.get("serial_number", ""))
        issuer = str(entry.get("issuer_name", ""))
        key = (serial, issuer)
        if key in seen or not serial:
            continue
        seen.add(key)
        try:
            not_before = datetime.fromisoformat(entry["not_before"]).replace(tzinfo=UTC)
            not_after = datetime.fromisoformat(entry["not_after"]).replace(tzinfo=UTC)
        except (KeyError, ValueError):
            continue
        # name_value is newline-separated SANs for this single certificate.
        for san in str(entry.get("name_value", "")).split("\n"):
            san = san.strip()
            if san:
                certs.append(
                    CertObservation(
                        san=san,
                        issuer=issuer,
                        not_before=not_before,
                        not_after=not_after,
                        serial_number=serial,
                    )
                )
    return CertHistory(certs=certs)


class CrtShProvider(Provider):
    name = "crtsh"
    supports = {IndicatorType.DOMAIN}
    rate_limit = RateLimit(max_requests=2, per_seconds=10)
    ttl = timedelta(hours=24)

    base_url = "https://crt.sh/"

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[CertHistory]:
        domain = target.value
        response = await self.request(
            "GET",
            self.base_url,
            params={"q": domain, "output": "json"},
            max_attempts=3,
            backoff_seconds=2.0,
        )
        try:
            entries = response.json()
        except ValueError as exc:
            raise ProviderError(f"crt.sh returned non-JSON response: {exc}") from exc
        if not isinstance(entries, list):
            raise ProviderError(f"crt.sh returned unexpected shape: {type(entries).__name__}")

        history = _parse_crtsh(entries)
        return ProviderResult(
            provider=self.name,
            raw={"entries": entries},
            normalized=history,
            fetched_at=datetime.now(UTC),
            partial=False,
        )

