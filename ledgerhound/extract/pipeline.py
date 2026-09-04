"""Extraction pipeline: raw_reports -> indicators + indicator_observations.

Runs `extract_from_payload` over every raw report in scope and upserts the
results:

- An indicator's `first_seen`/`last_seen` only ever widen (min/max against
  the report's `fetched_at`), regardless of processing order.
- An (indicator, raw_report) observation is created at most once, enforced
  both by a pre-check and by the DB unique constraint — so re-running
  extraction over the same reports is a no-op, not a duplicate-generator.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.db.models import Indicator, IndicatorObservation, IndicatorType, RawReport
from ledgerhound.extract.indicators import extract_from_payload

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ExtractionRunResult:
    reports_processed: int = 0
    indicators_created: int = 0
    indicators_reused: int = 0
    observations_created: int = 0
    observations_already_present: int = 0
    rejected_ip_count: int = 0


def _get_or_create_indicator(
    session: Session,
    *,
    itype: IndicatorType,
    value: str,
    defanged_value: str,
    observed_at: datetime,
) -> tuple[Indicator, bool]:
    """Return (indicator, created). Widens first_seen/last_seen if needed."""
    indicator = session.scalar(
        select(Indicator).where(Indicator.type == itype, Indicator.value == value)
    )
    if indicator is None:
        indicator = Indicator(
            type=itype,
            value=value,
            defanged_value=defanged_value,
            first_seen=observed_at,
            last_seen=observed_at,
        )
        session.add(indicator)
        session.flush()
        return indicator, True

    if observed_at < indicator.first_seen:
        indicator.first_seen = observed_at
    if observed_at > indicator.last_seen:
        indicator.last_seen = observed_at
    return indicator, False


def _ensure_observation(
    session: Session, *, indicator_id: object, raw_report_id: object, observed_at: datetime
) -> bool:
    """Return True if a new observation row was created, False if one already existed."""
    exists = session.scalar(
        select(IndicatorObservation.id).where(
            IndicatorObservation.indicator_id == indicator_id,
            IndicatorObservation.raw_report_id == raw_report_id,
        )
    )
    if exists is not None:
        return False
    session.add(
        IndicatorObservation(
            indicator_id=indicator_id, raw_report_id=raw_report_id, observed_at=observed_at
        )
    )
    session.flush()
    return True


def run_extraction(session: Session, *, since: datetime | None = None) -> ExtractionRunResult:
    """Run extraction over raw_reports (optionally filtered to fetched_at >= since)."""
    stmt = select(RawReport).order_by(RawReport.fetched_at)
    if since is not None:
        stmt = stmt.where(RawReport.fetched_at >= since)
    reports = session.scalars(stmt).all()

    reports_processed = 0
    indicators_created = 0
    indicators_reused = 0
    observations_created = 0
    observations_already_present = 0
    rejected_ip_count = 0

    for report in reports:
        reports_processed += 1
        extraction = extract_from_payload(report.payload)
        rejected_ip_count += len(extraction.rejected_ips)

        for extracted in extraction.indicators:
            indicator, created = _get_or_create_indicator(
                session,
                itype=extracted.type,
                value=extracted.value,
                defanged_value=extracted.defanged_value,
                observed_at=report.fetched_at,
            )
            indicators_created += created
            indicators_reused += not created

            observation_created = _ensure_observation(
                session,
                indicator_id=indicator.id,
                raw_report_id=report.id,
                observed_at=report.fetched_at,
            )
            observations_created += observation_created
            observations_already_present += not observation_created

    session.commit()

    result = ExtractionRunResult(
        reports_processed=reports_processed,
        indicators_created=indicators_created,
        indicators_reused=indicators_reused,
        observations_created=observations_created,
        observations_already_present=observations_already_present,
        rejected_ip_count=rejected_ip_count,
    )
    logger.info("extraction_run_complete", **asdict(result))
    return result
