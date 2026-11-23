"""Shared collection/extraction/enrichment summary statistics.

Computed once here so `lh stats` and the dashboard's `GET /api/stats`
endpoint can never disagree about what a number means, both call
`compute_stats`; neither re-derives the underlying queries.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ledgerhound.db.models import (
    AddressLabel,
    AddressProfile,
    DomainProfile,
    Indicator,
    IndicatorObservation,
    IndicatorType,
    RawReport,
    Source,
)
from ledgerhound.settings import Settings

_COVERAGE_TYPES = (
    IndicatorType.BTC_ADDRESS,
    IndicatorType.ETH_ADDRESS,
    IndicatorType.TRON_ADDRESS,
    IndicatorType.SOL_ADDRESS,
    IndicatorType.DOMAIN,
)


@dataclass(frozen=True, slots=True)
class SourceStats:
    name: str
    raw_report_count: int
    last_fetch: datetime | None


@dataclass(frozen=True, slots=True)
class IndicatorTypeCount:
    type: str
    count: int


@dataclass(frozen=True, slots=True)
class EnrichmentCoverage:
    type: str
    total: int
    enriched: int
    coverage_pct: float
    stale: int


@dataclass(frozen=True, slots=True)
class LabelTypeCount:
    label_type: str
    count: int


@dataclass(frozen=True, slots=True)
class StatsResult:
    sources: list[SourceStats]
    indicators_by_type: list[IndicatorTypeCount]
    total_indicators: int
    multi_source_indicator_count: int
    enrichment_coverage: list[EnrichmentCoverage]
    labels_by_type: list[LabelTypeCount]


def compute_stats(session: Session, settings: Settings) -> StatsResult:
    source_rows = session.execute(
        select(Source.name, func.count(RawReport.id), func.max(RawReport.fetched_at))
        .select_from(Source)
        .join(RawReport, RawReport.source_id == Source.id, isouter=True)
        .group_by(Source.id)
        .order_by(Source.name)
    ).all()
    sources = [
        SourceStats(name=name, raw_report_count=count, last_fetch=last_fetch)
        for name, count, last_fetch in source_rows
    ]

    indicator_rows = session.execute(
        select(Indicator.type, func.count(Indicator.id))
        .group_by(Indicator.type)
        .order_by(Indicator.type)
    ).all()
    indicators_by_type = [
        IndicatorTypeCount(type=itype.value, count=count) for itype, count in indicator_rows
    ]

    total_indicators = session.scalar(select(func.count(Indicator.id))) or 0

    multi_source_subq = (
        select(
            IndicatorObservation.indicator_id,
            func.count(func.distinct(RawReport.source_id)).label("source_count"),
        )
        .join(RawReport, RawReport.id == IndicatorObservation.raw_report_id)
        .group_by(IndicatorObservation.indicator_id)
        .subquery()
    )
    multi_source_count = (
        session.scalar(
            select(func.count())
            .select_from(multi_source_subq)
            .where(multi_source_subq.c.source_count > 1)
        )
        or 0
    )

    stale_before = datetime.now(UTC) - timedelta(hours=settings.enrich_default_ttl_hours)
    coverage: list[EnrichmentCoverage] = []
    for itype in _COVERAGE_TYPES:
        total = session.scalar(select(func.count(Indicator.id)).where(Indicator.type == itype)) or 0
        if itype == IndicatorType.DOMAIN:
            profile_query = select(DomainProfile.enriched_at).join(
                Indicator, Indicator.id == DomainProfile.indicator_id
            )
        else:
            profile_query = select(AddressProfile.enriched_at).join(
                Indicator, Indicator.id == AddressProfile.indicator_id
            )
        enriched_ats = list(session.scalars(profile_query.where(Indicator.type == itype)))
        enriched = len(enriched_ats)
        stale = sum(1 for ts in enriched_ats if ts < stale_before)
        pct = (enriched / total * 100) if total else 0.0
        coverage.append(
            EnrichmentCoverage(
                type=itype.value, total=total, enriched=enriched, coverage_pct=pct, stale=stale
            )
        )

    label_rows = session.execute(
        select(AddressLabel.label_type, func.count(AddressLabel.id))
        .group_by(AddressLabel.label_type)
        .order_by(AddressLabel.label_type)
    ).all()
    labels_by_type = [
        LabelTypeCount(label_type=label_type, count=count) for label_type, count in label_rows
    ]

    return StatsResult(
        sources=sources,
        indicators_by_type=indicators_by_type,
        total_indicators=total_indicators,
        multi_source_indicator_count=multi_source_count,
        enrichment_coverage=coverage,
        labels_by_type=labels_by_type,
    )

