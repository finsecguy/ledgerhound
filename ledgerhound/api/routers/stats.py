"""Overview/stats endpoint: wraps `ledgerhound.stats.compute_stats`, the
exact same function `lh stats` calls, plus a short list of recently-
active campaigns for the overview page."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.api.deps import get_session
from ledgerhound.api.schemas.stats import (
    CampaignActivityOut,
    OverviewOut,
    StatsCoverageOut,
    StatsIndicatorTypeOut,
    StatsLabelOut,
    StatsOut,
    StatsSourceOut,
)
from ledgerhound.db.models import Campaign
from ledgerhound.settings import get_settings
from ledgerhound.stats import StatsResult, compute_stats

router = APIRouter(prefix="/api", tags=["stats"])

_RECENT_CAMPAIGN_LIMIT = 10


def _stats_out(result: StatsResult) -> StatsOut:
    return StatsOut(
        sources=[
            StatsSourceOut(
                name=s.name,
                raw_report_count=s.raw_report_count,
                last_fetch=s.last_fetch.isoformat() if s.last_fetch else None,
            )
            for s in result.sources
        ],
        indicators_by_type=[
            StatsIndicatorTypeOut(type=row.type, count=row.count)
            for row in result.indicators_by_type
        ],
        total_indicators=result.total_indicators,
        multi_source_indicator_count=result.multi_source_indicator_count,
        enrichment_coverage=[
            StatsCoverageOut(
                type=row.type,
                total=row.total,
                enriched=row.enriched,
                coverage_pct=row.coverage_pct,
                stale=row.stale,
            )
            for row in result.enrichment_coverage
        ],
        labels_by_type=[
            StatsLabelOut(label_type=row.label_type, count=row.count)
            for row in result.labels_by_type
        ],
    )


@router.get("/stats", response_model=StatsOut)
def get_stats(session: Session = Depends(get_session)) -> StatsOut:
    settings = get_settings()
    result = compute_stats(session, settings)
    return _stats_out(result)


@router.get("/overview", response_model=OverviewOut)
def get_overview(session: Session = Depends(get_session)) -> OverviewOut:
    settings = get_settings()
    result = compute_stats(session, settings)
    recent = session.scalars(
        select(Campaign).order_by(Campaign.last_seen.desc()).limit(_RECENT_CAMPAIGN_LIMIT)
    )
    recent_out = [
        CampaignActivityOut(
            code=c.code,
            display_name=c.display_name,
            status=c.status,
            score=c.score,
            last_seen=c.last_seen.isoformat(),
        )
        for c in recent
    ]
    return OverviewOut(stats=_stats_out(result), recent_campaigns=recent_out)
