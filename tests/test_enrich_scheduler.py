"""Scheduler tests: token-bucket rate limiting (fake clock, no real sleep),
work selection priority/staleness, exact Decimal persistence, and
resumability — a run that fails partway through must not lose or
duplicate already-committed work."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.db.models import AddressProfile, Enrichment, Indicator, IndicatorType
from ledgerhound.enrich.base import (
    ChainAddressProfile,
    EnrichmentTarget,
    Provider,
    ProviderResult,
    RateLimit,
)
from ledgerhound.enrich.registry import ProviderRegistry
from ledgerhound.enrich.scheduler import TokenBucket, run_enrichment, select_work

# --- Token bucket: fake clock, no real sleep ---------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleep_calls: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        self.now += seconds


async def test_token_bucket_allows_burst_up_to_capacity_with_no_wait() -> None:
    clock = FakeClock()
    bucket = TokenBucket(3, 10, clock=clock)
    for _ in range(3):
        await bucket.acquire()
    assert clock.sleep_calls == []


async def test_token_bucket_waits_the_exact_deficit_when_exhausted() -> None:
    clock = FakeClock()
    bucket = TokenBucket(2, 10, clock=clock)  # refill rate: 0.2 tokens/sec
    await bucket.acquire()
    await bucket.acquire()
    await bucket.acquire()  # third request: bucket empty, must wait
    assert clock.sleep_calls == [5.0]  # 1 token deficit / 0.2 tokens-per-sec
    assert clock.now == 5.0


async def test_token_bucket_refills_over_time_without_overfilling() -> None:
    clock = FakeClock()
    bucket = TokenBucket(2, 10, clock=clock)
    await bucket.acquire()
    await bucket.acquire()
    clock.now += 100  # way more than enough to refill to capacity
    await bucket.acquire()
    await bucket.acquire()
    assert clock.sleep_calls == []  # both satisfied from the (capped) refill


# --- select_work: priority and staleness --------------------------------


def _make_indicator(session: Session, itype: IndicatorType, value: str) -> Indicator:
    ind = Indicator(
        type=itype, value=value, defanged_value=value, first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    session.add(ind)
    session.flush()
    return ind


def test_select_work_prioritizes_never_enriched_over_stale_refresh(db_session: Session) -> None:
    never_enriched = _make_indicator(db_session, IndicatorType.BTC_ADDRESS, "addr-new")
    stale = _make_indicator(db_session, IndicatorType.BTC_ADDRESS, "addr-stale")
    db_session.add(
        AddressProfile(
            indicator_id=stale.id,
            chain="btc",
            decimals=8,
            provider="test",
            enriched_at=datetime.now(UTC) - timedelta(days=10),
        )
    )
    db_session.commit()

    work = select_work(db_session, ttl=timedelta(hours=6))

    assert [w.indicator_id for w in work] == [never_enriched.id, stale.id]


def test_select_work_skips_fresh_indicators_unless_forced(db_session: Session) -> None:
    fresh = _make_indicator(db_session, IndicatorType.BTC_ADDRESS, "addr-fresh")
    db_session.add(
        AddressProfile(
            indicator_id=fresh.id,
            chain="btc",
            decimals=8,
            provider="test",
            enriched_at=datetime.now(UTC),
        )
    )
    db_session.commit()

    assert select_work(db_session, ttl=timedelta(hours=6)) == []
    forced = select_work(db_session, ttl=timedelta(hours=6), force=True)
    assert len(forced) == 1


# --- Exact Decimal persistence ------------------------------------------


class _FixedValueEthProvider(Provider):
    name = "fixed_eth"
    supports = {IndicatorType.ETH_ADDRESS}
    rate_limit = RateLimit(max_requests=1000, per_seconds=1)
    ttl = timedelta(hours=1)

    def __init__(self, value: Decimal, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._value = value

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
        return ProviderResult(
            provider=self.name,
            raw={},
            normalized=ChainAddressProfile(
                chain="eth",
                address=target.value,
                decimals=18,
                total_received=self._value,
                current_balance=self._value,
            ),
            fetched_at=datetime.now(UTC),
        )


async def test_eighteen_decimal_wei_amount_persists_exactly(db_session: Session) -> None:
    indicator = _make_indicator(
        db_session, IndicatorType.ETH_ADDRESS, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    )
    db_session.commit()

    exact_value = Decimal("123456789012345678901234567.123456789012345678")
    registry = ProviderRegistry(
        {"eth_address": [_FixedValueEthProvider(exact_value, client=None)]}  # type: ignore[arg-type]
    )

    await run_enrichment(db_session, registry)

    db_session.expire_all()
    profile = db_session.scalar(
        select(AddressProfile).where(AddressProfile.indicator_id == indicator.id)
    )
    assert profile is not None
    assert profile.current_balance == exact_value
    assert profile.total_received == exact_value
    assert isinstance(profile.current_balance, Decimal)


# --- Resumability ---------------------------------------------------------


class _CountingProvider(Provider):
    """Always succeeds; just records which addresses it was asked to
    enrich, so a test can tell exactly what work happened in each run."""

    name = "counting"
    supports = {IndicatorType.BTC_ADDRESS}
    rate_limit = RateLimit(max_requests=1000, per_seconds=1)
    ttl = timedelta(hours=1)

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.calls: list[str] = []

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
        self.calls.append(target.value)
        return ProviderResult(
            provider=self.name,
            raw={},
            normalized=ChainAddressProfile(chain="btc", address=target.value, decimals=8),
            fetched_at=datetime.now(UTC),
        )


async def test_resumability_interrupted_run_then_rerun_has_no_duplicates_or_loss(
    db_session: Session,
) -> None:
    """Models a process killed partway through a batch (here, via
    `limit=2` standing in for "only got through 2 of 3 before dying") —
    the interrupted run's progress must survive, and resuming must finish
    exactly the remainder without re-touching or duplicating what already
    committed."""
    ind_a = _make_indicator(db_session, IndicatorType.BTC_ADDRESS, "addr-a")
    ind_b = _make_indicator(db_session, IndicatorType.BTC_ADDRESS, "addr-b")
    ind_c = _make_indicator(db_session, IndicatorType.BTC_ADDRESS, "addr-c")
    db_session.commit()
    all_ids = {ind_a.id, ind_b.id, ind_c.id}

    interrupted_run_provider = _CountingProvider(client=None)  # type: ignore[arg-type]
    registry = ProviderRegistry({"btc_address": [interrupted_run_provider]})

    first_run = await run_enrichment(db_session, registry, limit=2)
    assert first_run.attempted == 2
    assert first_run.succeeded == 2

    profiles_after_first_run = {
        p.indicator_id: p for p in db_session.scalars(select(AddressProfile))
    }
    assert len(profiles_after_first_run) == 2  # exactly the two processed so far

    # "Restart": a fresh provider instance (as a real restarted process
    # would have), re-run enrichment with no limit this time.
    resumed_run_provider = _CountingProvider(client=None)  # type: ignore[arg-type]
    registry2 = ProviderRegistry({"btc_address": [resumed_run_provider]})
    second_run = await run_enrichment(db_session, registry2)

    # Only the one indicator the interrupted run never reached is picked
    # up — the other two are already fresh and must not be redone.
    assert second_run.attempted == 1
    remaining_id = all_ids - set(profiles_after_first_run)
    remaining_value = next(
        v.value for v in (ind_a, ind_b, ind_c) if v.id == next(iter(remaining_id))
    )
    assert resumed_run_provider.calls == [remaining_value]

    db_session.expire_all()
    final_profiles = list(db_session.scalars(select(AddressProfile)))
    assert len(final_profiles) == 3  # exactly one row per indicator, no dupes
    assert {p.indicator_id for p in final_profiles} == all_ids

    for indicator_id in all_ids:
        enrichment_rows = list(
            db_session.scalars(select(Enrichment).where(Enrichment.indicator_id == indicator_id))
        )
        assert len(enrichment_rows) == 1  # one successful attempt recorded, not two
