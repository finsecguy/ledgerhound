"""Provider selection: fallback chains keyed by enrichment "facet", with
per-provider health tracking (consecutive failures, cooldown) so an
unhealthy provider is skipped automatically and retried after backing off.

**Why "facet" and not just `IndicatorType`:** a chain address has exactly
one kind of profile to fetch (balance/history/counterparties), so its
fallback chain is naturally keyed by `IndicatorType`. A domain has *four*
independent kinds of data (DNS, RDAP, certificates, HTTP fingerprint),
each with its own provider(s) and its own normalized shape. They are not
alternatives for the same question, they're different questions. Modeling
each as its own facet keeps `Provider.enrich()` returning exactly one
normalized shape (per the base contract) while still letting a domain
collect all four independently, each with its own two-provider redundancy
where a real alternative source exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import structlog
import yaml
from pydantic import BaseModel, Field

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget, Provider, ProviderResult

logger = structlog.get_logger(__name__)

#: Which facets apply to each indicator type. Chain types have exactly one
#: facet (their address profile); domains fan out into four independent
#: facets; URL/Telegram indicators have no enrichment source in this
#: milestone (a URL's *host* is enriched as its own DOMAIN indicator).
FACETS_BY_INDICATOR_TYPE: dict[IndicatorType, tuple[str, ...]] = {
    IndicatorType.BTC_ADDRESS: ("btc_address",),
    IndicatorType.ETH_ADDRESS: ("eth_address",),
    IndicatorType.TRON_ADDRESS: ("tron_address",),
    IndicatorType.SOL_ADDRESS: ("sol_address",),
    IndicatorType.DOMAIN: ("domain_dns", "domain_rdap", "domain_certs", "domain_http"),
    IndicatorType.URL: (),
    IndicatorType.TELEGRAM_HANDLE: (),
}


class ProviderConfigEntry(BaseModel):
    max_requests: int = Field(gt=0)
    per_seconds: float = Field(gt=0)
    ttl_hours: float = Field(gt=0)


class ProvidersConfig(BaseModel):
    providers: dict[str, ProviderConfigEntry]


def load_providers_config(path: Path) -> dict[str, ProviderConfigEntry]:
    """Load per-provider rate-limit/TTL overrides from config/providers.yaml.

    Providers ship with sensible defaults baked into their class
    definitions; this file exists so limits can be tuned without a code
    change, not because a provider is unusable without it.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return ProvidersConfig.model_validate(raw).providers


@dataclass(slots=True)
class ProviderHealth:
    consecutive_failures: int = 0
    last_success: datetime | None = None
    last_failure: datetime | None = None
    cooldown_until: datetime | None = None

    def is_available(self, now: datetime) -> bool:
        return self.cooldown_until is None or now >= self.cooldown_until


#: Exponential backoff cooldown after N consecutive failures, capped so a
#: provider that's been down for a while is still retried periodically
#: rather than permanently benched.
_BASE_COOLDOWN = timedelta(seconds=30)
_MAX_COOLDOWN = timedelta(minutes=30)


def _cooldown_for(consecutive_failures: int) -> timedelta:
    seconds = _BASE_COOLDOWN.total_seconds() * (2 ** (consecutive_failures - 1))
    return timedelta(seconds=min(seconds, _MAX_COOLDOWN.total_seconds()))


class NoProviderAvailable(Exception):
    def __init__(self, facet: str) -> None:
        super().__init__(f"No healthy provider available for facet {facet!r}")
        self.facet = facet


class _RateLimiter(Protocol):
    async def acquire(self) -> None: ...


class ProviderRegistry:
    """Per-facet fallback chains with per-provider health tracking."""

    def __init__(
        self,
        chains: dict[str, list[Provider]],
        *,
        rate_limiters: Mapping[str, _RateLimiter] | None = None,
    ) -> None:
        self._chains = chains
        self._health: dict[str, ProviderHealth] = {}
        for providers in chains.values():
            for provider in providers:
                self._health.setdefault(provider.name, ProviderHealth())
        #: Optional per-provider-name token bucket, applied immediately
        #: before that provider is actually called (not before every
        #: chain member, only the one that ends up serving the request
        #: consumes a token). Built and owned by the scheduler.
        self._rate_limiters = rate_limiters or {}

    def chain_for(self, facet: str) -> list[Provider]:
        return list(self._chains.get(facet, []))

    def restricted_to(self, provider_name: str) -> ProviderRegistry:
        """A copy of this registry where every facet's chain is filtered
        down to just `provider_name` (facets that provider doesn't serve
        are dropped entirely). Used by `lh enrich --provider NAME` to force
        a single source instead of the normal fallback chain."""
        filtered = {
            facet: matches
            for facet, providers in self._chains.items()
            if (matches := [p for p in providers if p.name == provider_name])
        }
        return ProviderRegistry(filtered, rate_limiters=self._rate_limiters)

    def facets(self) -> list[str]:
        return sorted(self._chains)

    def health_snapshot(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        facets_by_provider: dict[str, set[str]] = {}
        for facet, providers in self._chains.items():
            for provider in providers:
                facets_by_provider.setdefault(provider.name, set()).add(facet)

        return [
            {
                "provider": name,
                "facets": sorted(facets_by_provider.get(name, set())),
                "healthy": health.is_available(now),
                "consecutive_failures": health.consecutive_failures,
                "last_success": health.last_success,
                "cooldown_until": health.cooldown_until,
            }
            for name, health in sorted(self._health.items())
        ]

    async def enrich(
        self, target: EnrichmentTarget, facet: str, *, now: datetime | None = None
    ) -> ProviderResult[Any]:
        """Try each provider in `facet`'s chain in order; the first healthy
        provider that succeeds wins. Every failure (exception of any kind)
        marks that provider unhealthy for a backoff window and falls
        through to the next; a fallback being used is logged explicitly so
        it's visible which provider actually served the data."""
        now = now or datetime.now(UTC)
        chain = self._chains.get(facet, [])
        if not chain:
            raise NoProviderAvailable(facet)

        last_exc: Exception | None = None
        for index, provider in enumerate(chain):
            health = self._health[provider.name]
            if not health.is_available(now):
                logger.debug(
                    "provider_in_cooldown", provider=provider.name, until=health.cooldown_until
                )
                continue
            limiter = self._rate_limiters.get(provider.name)
            if limiter is not None:
                await limiter.acquire()
            try:
                result = await provider.enrich(target)
            except Exception as exc:  # noqa: BLE001 - any failure triggers fallback
                health.consecutive_failures += 1
                health.last_failure = now
                health.cooldown_until = now + _cooldown_for(health.consecutive_failures)
                logger.warning(
                    "provider_failed",
                    provider=provider.name,
                    facet=facet,
                    error=str(exc),
                    consecutive_failures=health.consecutive_failures,
                    cooldown_until=health.cooldown_until.isoformat(),
                )
                last_exc = exc
                continue

            health.consecutive_failures = 0
            health.last_success = now
            health.cooldown_until = None
            if index > 0:
                logger.info(
                    "provider_fallback_served",
                    provider=provider.name,
                    facet=facet,
                    fallback_depth=index,
                )
            return result

        raise NoProviderAvailable(facet) from last_exc

