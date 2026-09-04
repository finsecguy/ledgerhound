"""Enrichment scheduling: which indicators need work, at what pace, with
what concurrency — and safely resumable if the run is killed partway
through.

**Resumability by construction, not by a separate checkpoint mechanism:**
each indicator's enrichment result is committed to the database as soon
as it's fetched, one indicator at a time (serialized — a `Session` isn't
safe to share across concurrently-running tasks). If the process dies
after N indicators, those N are durably persisted and the next run's
"needs enrichment" query naturally skips them and picks up where it left
off; nothing is re-fetched, nothing is left half-written.

**Concurrency** is bounded at the network-fetch level via a semaphore —
many indicators' provider calls can be in flight at once — while the
database write for each result is serialized behind a lock.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

import structlog
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ledgerhound.db.models import (
    AddressCounterparty,
    AddressLabel,
    AddressProfile,
    DomainCert,
    DomainProfile,
    Enrichment,
    Indicator,
    IndicatorType,
)
from ledgerhound.enrich.base import (
    AddressLabelHit,
    ChainAddressProfile,
    EnrichmentTarget,
    ProviderResult,
)
from ledgerhound.enrich.infra.certs import CertHistory
from ledgerhound.enrich.infra.dns import DnsRecords
from ledgerhound.enrich.infra.http import HttpFingerprint
from ledgerhound.enrich.infra.whois import DomainRegistrationProfile
from ledgerhound.enrich.labels.known import KnownAddressIndex
from ledgerhound.enrich.labels.ofac import OFACList
from ledgerhound.enrich.registry import (
    FACETS_BY_INDICATOR_TYPE,
    NoProviderAvailable,
    ProviderRegistry,
)

logger = structlog.get_logger(__name__)

_ENRICHABLE_TYPES = {
    IndicatorType.BTC_ADDRESS,
    IndicatorType.ETH_ADDRESS,
    IndicatorType.TRON_ADDRESS,
    IndicatorType.SOL_ADDRESS,
    IndicatorType.DOMAIN,
}
_CHAIN_BY_TYPE = {
    IndicatorType.BTC_ADDRESS: "btc",
    IndicatorType.ETH_ADDRESS: "eth",
    IndicatorType.TRON_ADDRESS: "tron",
    IndicatorType.SOL_ADDRESS: "sol",
}


# --- Rate limiting -----------------------------------------------------


class Clock(Protocol):
    def monotonic(self) -> float: ...
    async def sleep(self, seconds: float) -> None: ...


class RealClock:
    def monotonic(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class TokenBucket:
    """Classic token bucket: `max_requests` tokens, refilled continuously
    over `per_seconds`, one token consumed per `acquire()`.

    Takes a `Clock` rather than calling `time.monotonic()`/`asyncio.sleep`
    directly so tests can drive it with a fake clock instead of actually
    waiting — real time never has to pass to verify the limiter's math.
    """

    def __init__(
        self, max_requests: int, per_seconds: float, *, clock: Clock | None = None
    ) -> None:
        self._capacity = float(max_requests)
        self._refill_rate = max_requests / per_seconds  # tokens per second
        self._tokens = float(max_requests)
        self._clock = clock or RealClock()
        self._last_refill = self._clock.monotonic()
        self._lock = asyncio.Lock()

    def _refill_locked(self) -> None:
        now = self._clock.monotonic()
        elapsed = max(0.0, now - self._last_refill)
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                self._refill_locked()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait_time = (1 - self._tokens) / self._refill_rate
            await self._clock.sleep(wait_time)


# --- Work selection ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WorkItem:
    indicator_id: UUID
    indicator_type: IndicatorType
    value: str


def select_work(
    session: Session,
    *,
    indicator_types: set[IndicatorType] | None = None,
    limit: int | None = None,
    force: bool = False,
    ttl: timedelta = timedelta(hours=6),
) -> list[WorkItem]:
    """Indicators needing enrichment: never enriched, or last enriched
    before `ttl` ago. Never-enriched indicators sort first (new indicators
    take priority over refreshing old ones), then oldest-enriched first.
    """
    types = indicator_types & _ENRICHABLE_TYPES if indicator_types else _ENRICHABLE_TYPES
    if not types:
        return []

    now = datetime.now(UTC)
    stale_before = now - ttl

    address_profile_by_indicator = {
        row.indicator_id: row.enriched_at
        for row in session.scalars(select(AddressProfile))
    }
    domain_profile_by_indicator = {
        row.indicator_id: row.enriched_at
        for row in session.scalars(select(DomainProfile))
    }

    candidates: list[tuple[bool, datetime, WorkItem]] = []
    for indicator in session.scalars(select(Indicator).where(Indicator.type.in_(types))):
        enriched_at = (
            address_profile_by_indicator.get(indicator.id)
            if indicator.type != IndicatorType.DOMAIN
            else domain_profile_by_indicator.get(indicator.id)
        )
        never_enriched = enriched_at is None
        is_fresh = enriched_at is not None and enriched_at >= stale_before
        if not force and not never_enriched and is_fresh:
            continue  # fresh enough, skip
        sort_key_time = enriched_at or datetime.fromtimestamp(0, tz=UTC)
        candidates.append(
            (
                not never_enriched,  # False (never enriched) sorts before True (refresh)
                sort_key_time,
                WorkItem(
                    indicator_id=indicator.id,
                    indicator_type=indicator.type,
                    value=indicator.value,
                ),
            )
        )

    candidates.sort(key=lambda c: (c[0], c[1]))
    items = [c[2] for c in candidates]
    return items[:limit] if limit is not None else items


# --- Persistence (one indicator's worth, committed atomically) -------------


def _persist_chain_result(
    session: Session,
    item: WorkItem,
    result: ProviderResult[ChainAddressProfile],
    *,
    ofac: OFACList | None,
    known: KnownAddressIndex | None,
) -> None:
    profile = result.normalized
    chain = _CHAIN_BY_TYPE[item.indicator_type]

    session.add(
        Enrichment(
            indicator_id=item.indicator_id,
            provider=result.provider,
            payload=result.raw,
            fetched_at=result.fetched_at,
        )
    )

    existing = session.scalar(
        select(AddressProfile).where(AddressProfile.indicator_id == item.indicator_id)
    )
    if existing is None:
        existing = AddressProfile(indicator_id=item.indicator_id, chain=chain)
        session.add(existing)
    existing.first_seen_onchain = profile.first_seen_onchain
    existing.last_seen_onchain = profile.last_seen_onchain
    existing.tx_count = profile.tx_count
    existing.total_received = profile.total_received
    existing.total_sent = profile.total_sent
    existing.current_balance = profile.current_balance
    existing.decimals = profile.decimals
    existing.provider = result.provider
    existing.enriched_at = result.fetched_at

    session.execute(
        delete(AddressCounterparty).where(AddressCounterparty.indicator_id == item.indicator_id)
    )
    for counterparty in profile.counterparties:
        session.add(
            AddressCounterparty(
                indicator_id=item.indicator_id,
                counterparty_address=counterparty.address,
                direction=counterparty.direction,
                tx_count=counterparty.tx_count,
                total_value=counterparty.total_value,
            )
        )

    for source_name, hit in _label_hits(chain, item.value, ofac=ofac, known=known):
        exists = session.scalar(
            select(AddressLabel).where(
                AddressLabel.indicator_id == item.indicator_id,
                AddressLabel.label == hit.label,
                AddressLabel.source == source_name,
            )
        )
        if exists is None:
            session.add(
                AddressLabel(
                    indicator_id=item.indicator_id,
                    label=hit.label,
                    label_type=hit.label_type,
                    source=source_name,
                    confidence=hit.confidence,
                )
            )


def _label_hits(
    chain: str, address: str, *, ofac: OFACList | None, known: KnownAddressIndex | None
) -> list[tuple[str, AddressLabelHit]]:
    hits: list[tuple[str, AddressLabelHit]] = []
    if ofac is not None:
        ofac_hit = ofac.lookup(chain, address)  # type: ignore[arg-type]
        if ofac_hit is not None:
            hits.append(
                (
                    "OFAC SDN list",
                    AddressLabelHit(
                        label=ofac_hit.entity_name or "OFAC SDN",
                        label_type="sanctioned",
                        source="OFAC SDN list",
                        confidence=1.0,
                    ),
                )
            )
    if known is not None:
        known_hit = known.lookup(chain, address)  # type: ignore[arg-type]
        if known_hit is not None:
            hits.append((known_hit.source, known_hit))
    return hits


DomainFacetResult = (
    ProviderResult[DnsRecords]
    | ProviderResult[DomainRegistrationProfile]
    | ProviderResult[CertHistory]
    | ProviderResult[HttpFingerprint]
)


def _persist_domain_facets(
    session: Session,
    item: WorkItem,
    facet_results: dict[str, DomainFacetResult],
) -> None:
    for result in facet_results.values():
        session.add(
            Enrichment(
                indicator_id=item.indicator_id,
                provider=result.provider,
                payload=result.raw,
                fetched_at=result.fetched_at,
            )
        )

    existing = session.scalar(
        select(DomainProfile).where(DomainProfile.indicator_id == item.indicator_id)
    )
    if existing is None:
        existing = DomainProfile(indicator_id=item.indicator_id)
        session.add(existing)

    now = datetime.now(UTC)
    existing.enriched_at = now

    dns_result = facet_results.get("domain_dns")
    dns_ns: list[str] = []
    if dns_result is not None:
        dns_records: DnsRecords = dns_result.normalized  # type: ignore[assignment]
        dns_ns = dns_records.ns
        existing.ns_records = dns_records.ns
        existing.asn = dns_records.asn
        existing.nxdomain = dns_records.nxdomain

    registration_result = facet_results.get("domain_rdap")
    if registration_result is not None:
        registration: DomainRegistrationProfile = registration_result.normalized  # type: ignore[assignment]
        existing.registrar = registration.registrar
        existing.domain_created_at = registration.created_at
        existing.domain_updated_at = registration.updated_at
        existing.domain_expires_at = registration.expires_at
        existing.registrant_country = registration.registrant_country
        existing.registrant_redacted = registration.redacted
        existing.registered = registration.registered
        existing.status = registration.status
        existing.registration_provider = registration_result.provider
        # RDAP/WHOIS nameservers are the registry's authoritative record;
        # DNS's are what's actually resolving live right now. Both are
        # informative and usually agree — union rather than pick one.
        existing.ns_records = sorted(set(dns_ns) | set(registration.nameservers))

    http_result = facet_results.get("domain_http")
    if http_result is not None:
        fingerprint: HttpFingerprint = http_result.normalized  # type: ignore[assignment]
        existing.http_status = fingerprint.status
        existing.http_server_header = fingerprint.server_header
        existing.body_hash = fingerprint.body_hash
        existing.favicon_hash = fingerprint.favicon_hash

    certs_result = facet_results.get("domain_certs")
    if certs_result is not None:
        cert_history: CertHistory = certs_result.normalized  # type: ignore[assignment]
        session.execute(delete(DomainCert).where(DomainCert.indicator_id == item.indicator_id))
        for cert in cert_history.certs:
            session.add(
                DomainCert(
                    indicator_id=item.indicator_id,
                    san=cert.san,
                    issuer=cert.issuer,
                    not_before=cert.not_before,
                    not_after=cert.not_after,
                    serial_number=cert.serial_number,
                )
            )


# --- Orchestration -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SchedulerRunResult:
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped_no_provider: int = 0


async def run_enrichment(
    session: Session,
    registry: ProviderRegistry,
    *,
    indicator_types: set[IndicatorType] | None = None,
    limit: int | None = None,
    force: bool = False,
    ttl: timedelta = timedelta(hours=6),
    concurrency: int = 5,
    ofac: OFACList | None = None,
    known: KnownAddressIndex | None = None,
) -> SchedulerRunResult:
    work_items = select_work(
        session, indicator_types=indicator_types, limit=limit, force=force, ttl=ttl
    )

    attempted = succeeded = failed = skipped_no_provider = 0
    semaphore = asyncio.Semaphore(concurrency)
    db_lock = asyncio.Lock()

    async def process(item: WorkItem) -> str:
        nonlocal attempted
        async with semaphore:
            attempted += 1
            target = EnrichmentTarget(
                indicator_id=item.indicator_id, type=item.indicator_type, value=item.value
            )
            try:
                if item.indicator_type == IndicatorType.DOMAIN:
                    facet_results = {}
                    for facet in FACETS_BY_INDICATOR_TYPE[IndicatorType.DOMAIN]:
                        try:
                            facet_results[facet] = await registry.enrich(target, facet)
                        except NoProviderAvailable:
                            logger.warning("facet_unavailable", facet=facet, value=item.value)
                    if not facet_results:
                        return "skipped_no_provider"
                    async with db_lock:
                        _persist_domain_facets(session, item, facet_results)
                        session.commit()
                    return "succeeded"
                else:
                    facet = item.indicator_type.value
                    result = await registry.enrich(target, facet)
                    async with db_lock:
                        _persist_chain_result(session, item, result, ofac=ofac, known=known)
                        session.commit()
                    return "succeeded"
            except NoProviderAvailable:
                return "skipped_no_provider"
            except Exception:
                logger.exception(
                    "enrichment_failed", indicator_id=str(item.indicator_id), value=item.value
                )
                async with db_lock:
                    session.rollback()
                return "failed"

    outcomes = await asyncio.gather(*(process(item) for item in work_items))
    for outcome in outcomes:
        if outcome == "succeeded":
            succeeded += 1
        elif outcome == "failed":
            failed += 1
        elif outcome == "skipped_no_provider":
            skipped_no_provider += 1

    result = SchedulerRunResult(
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        skipped_no_provider=skipped_no_provider,
    )
    logger.info("enrichment_run_complete", **asdict(result))
    return result
