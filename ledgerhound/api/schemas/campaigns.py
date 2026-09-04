"""Response/request models for the campaigns resource."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class CampaignSummary(BaseModel):
    code: str
    display_name: str | None
    status: str
    score: float
    member_count: int
    relation_types: list[str]
    first_seen: datetime
    last_seen: datetime


class CampaignListResponse(BaseModel):
    campaigns: list[CampaignSummary]
    total: int


class CampaignMemberOut(BaseModel):
    indicator_id: str
    type: str
    value: str
    joined_at: datetime


class CampaignEventOut(BaseModel):
    event_type: str
    occurred_at: datetime
    related_campaign_codes: list[str]
    members_before_count: int
    members_after_count: int


class AssessmentStatusOut(BaseModel):
    version: int
    status: str
    stale: bool
    edited_by_human: bool
    reviewed_by: str | None
    reviewed_at: datetime | None


class CampaignDetail(BaseModel):
    code: str
    display_name: str | None
    status: str
    score: float
    relation_types: list[str]
    first_seen: datetime
    last_seen: datetime
    members: list[CampaignMemberOut]
    events: list[CampaignEventOut]
    latest_assessment: AssessmentStatusOut | None
    approved_assessment: AssessmentStatusOut | None


class DisplayNameUpdate(BaseModel):
    display_name: str | None
