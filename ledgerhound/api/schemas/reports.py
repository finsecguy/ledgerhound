"""Response models for reports and the IOC feed."""

from __future__ import annotations

from pydantic import BaseModel


class ReportMeta(BaseModel):
    campaign_code: str
    has_markdown: bool
    has_pdf: bool
    markdown: str | None
    pdf_url: str | None


class FeedCampaignSummary(BaseModel):
    campaign: str
    status: str
    last_seen: str
    indicator_count: int


class FeedIndexOut(BaseModel):
    campaign_count: int
    campaigns: list[FeedCampaignSummary]
