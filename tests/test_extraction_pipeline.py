"""Extraction pipeline idempotency: running twice must not duplicate
observations or corrupt first_seen/last_seen."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ledgerhound.db.models import (
    Indicator,
    IndicatorObservation,
    IndicatorType,
    RawReport,
    Source,
    SourceType,
)
from ledgerhound.extract.pipeline import run_extraction

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = T0 + timedelta(days=1)


def _make_source(session: Session) -> Source:
    source = Source(
        name="test-source",
        type=SourceType.PHISHING_FEED,
        url="https://example.invalid/feed",
        cadence_minutes=60,
        reliability_grade="B",
        enabled=True,
    )
    session.add(source)
    session.flush()
    return source


def _make_report(
    session: Session, source: Source, fetched_at: datetime, payload: dict
) -> RawReport:
    report = RawReport(
        source_id=source.id,
        payload=payload,
        content_hash=f"hash-{fetched_at.isoformat()}-{payload}",
        fetched_at=fetched_at,
    )
    session.add(report)
    session.flush()
    return report


def test_extraction_is_idempotent_on_repeated_runs(db_session: Session) -> None:
    source = _make_source(db_session)
    _make_report(
        db_session,
        source,
        T0,
        {"note": "phishing site trust-wallet-bnb.vercel.app used address "
                 "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
    )

    first = run_extraction(db_session)
    second = run_extraction(db_session)

    assert first.indicators_created == 2
    assert first.observations_created == 2
    assert second.indicators_created == 0
    assert second.observations_created == 0
    assert second.observations_already_present == 2

    indicator_count = db_session.scalar(select(func.count(Indicator.id)))
    observation_count = db_session.scalar(select(func.count(IndicatorObservation.id)))
    assert indicator_count == 2
    assert observation_count == 2


def test_extraction_widens_first_seen_and_last_seen_across_reports(db_session: Session) -> None:
    source = _make_source(db_session)
    domain = "trust-wallet-bnb.vercel.app"
    _make_report(db_session, source, T1, {"note": f"seen at {domain}"})
    run_extraction(db_session)

    indicator = db_session.scalar(
        select(Indicator).where(Indicator.type == IndicatorType.DOMAIN, Indicator.value == domain)
    )
    assert indicator is not None
    assert indicator.first_seen == T1
    assert indicator.last_seen == T1

    # An earlier-dated report observed later should widen first_seen backward
    # without disturbing last_seen, regardless of processing order.
    _make_report(db_session, source, T0, {"note": f"also seen at {domain}"})
    run_extraction(db_session)

    db_session.refresh(indicator)
    assert indicator.first_seen == T0
    assert indicator.last_seen == T1


def test_extraction_creates_one_observation_per_report_not_per_mention(db_session: Session) -> None:
    source = _make_source(db_session)
    domain = "trust-wallet-bnb.vercel.app"
    _make_report(
        db_session, source, T0, {"note": f"{domain} appears twice: see {domain} again"}
    )

    result = run_extraction(db_session)

    assert result.indicators_created == 1
    assert result.observations_created == 1
    observation_count = db_session.scalar(select(func.count(IndicatorObservation.id)))
    assert observation_count == 1
