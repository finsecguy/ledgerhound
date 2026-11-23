"""Response models for `/api/stats`, mirroring `ledgerhound.stats.StatsResult`
field-for-field, the API never recomputes these numbers, only shapes
`compute_stats`'s output as JSON."""

from __future__ import annotations

from pydantic import BaseModel


class StatsSourceOut(BaseModel):
    name: str
    raw_report_count: int
    last_fetch: str | None


class StatsIndicatorTypeOut(BaseModel):
    type: str
    count: int


class StatsCoverageOut(BaseModel):
    type: str
    total: int
    enriched: int
    coverage_pct: float
    stale: int


class StatsLabelOut(BaseModel):
    label_type: str
    count: int


class StatsOut(BaseModel):
    sources: list[StatsSourceOut]
    indicators_by_type: list[StatsIndicatorTypeOut]
    total_indicators: int
    multi_source_indicator_count: int
    enrichment_coverage: list[StatsCoverageOut]
    labels_by_type: list[StatsLabelOut]


class CampaignActivityOut(BaseModel):
    """Recent campaign activity for the overview page, the same fields
    `CampaignSummary` carries, so the frontend can reuse one campaign-card
    component for both the overview and list pages."""

    code: str
    display_name: str | None
    status: str
    score: float
    last_seen: str


class OverviewOut(BaseModel):
    stats: StatsOut
    recent_campaigns: list[CampaignActivityOut]

