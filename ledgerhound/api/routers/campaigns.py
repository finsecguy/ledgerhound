"""Campaign list/detail/rename. Presentational queries only, no
clustering, scoring, or evidence-pack logic lives here (see the module
docstring in `ledgerhound/api/__init__.py`)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ledgerhound.api.deps import get_session
from ledgerhound.api.schemas.campaigns import (
    AssessmentStatusOut,
    CampaignDetail,
    CampaignEventOut,
    CampaignListResponse,
    CampaignMemberOut,
    CampaignSummary,
    DisplayNameUpdate,
)
from ledgerhound.db.models import Assessment, Campaign, CampaignEvent, CampaignMember, Indicator

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])


def get_campaign_or_404(session: Session, code: str) -> Campaign:
    campaign = session.scalar(select(Campaign).where(Campaign.code == code))
    if campaign is None:
        raise HTTPException(status_code=404, detail=f"No campaign with code {code!r}")
    return campaign


def _assessment_status_out(assessment: Assessment) -> AssessmentStatusOut:
    return AssessmentStatusOut(
        version=assessment.version,
        status=assessment.status,
        stale=assessment.stale,
        edited_by_human=assessment.edited_by_human,
        reviewed_by=assessment.reviewed_by,
        reviewed_at=assessment.reviewed_at,
    )


def _build_campaign_detail(session: Session, campaign: Campaign) -> CampaignDetail:
    members = list(
        session.scalars(select(CampaignMember).where(CampaignMember.campaign_id == campaign.id))
    )
    indicator_ids = [m.indicator_id for m in members]
    indicators_by_id = {
        i.id: i for i in session.scalars(select(Indicator).where(Indicator.id.in_(indicator_ids)))
    }
    member_out = [
        CampaignMemberOut(
            indicator_id=str(member.indicator_id),
            type=indicators_by_id[member.indicator_id].type.value,
            value=indicators_by_id[member.indicator_id].value,
            joined_at=member.joined_at,
        )
        for member in sorted(members, key=lambda m: str(m.indicator_id))
        if member.indicator_id in indicators_by_id
    ]

    events = list(
        session.scalars(
            select(CampaignEvent)
            .where(CampaignEvent.campaign_id == campaign.id)
            .order_by(CampaignEvent.occurred_at)
        )
    )
    events_out = [
        CampaignEventOut(
            event_type=event.event_type,
            occurred_at=event.occurred_at,
            related_campaign_codes=event.related_campaign_codes,
            members_before_count=len(event.members_before),
            members_after_count=len(event.members_after),
        )
        for event in events
    ]

    assessments = list(
        session.scalars(
            select(Assessment)
            .where(Assessment.campaign_id == campaign.id)
            .order_by(Assessment.version.desc())
        )
    )
    latest = assessments[0] if assessments else None
    approved = next((a for a in assessments if a.status == "approved"), None)

    return CampaignDetail(
        code=campaign.code,
        display_name=campaign.display_name,
        status=campaign.status,
        score=campaign.score,
        relation_types=campaign.relation_types,
        first_seen=campaign.first_seen,
        last_seen=campaign.last_seen,
        members=member_out,
        events=events_out,
        latest_assessment=_assessment_status_out(latest) if latest else None,
        approved_assessment=_assessment_status_out(approved) if approved else None,
    )


@router.get("", response_model=CampaignListResponse)
def list_campaigns(
    status: str | None = Query(None, description="Filter: active or dormant."),
    min_size: int = Query(0, ge=0, description="Only campaigns with at least N members."),
    search: str | None = Query(
        None, description="Match against code, display name, or a member's value."
    ),
    session: Session = Depends(get_session),
) -> CampaignListResponse:
    if status is not None and status not in ("active", "dormant"):
        raise HTTPException(status_code=400, detail="status must be 'active' or 'dormant'")

    query = select(Campaign)
    if status is not None:
        query = query.where(Campaign.status == status)
    if search:
        pattern = f"%{search}%"
        matching_member_campaign_ids = (
            select(CampaignMember.campaign_id)
            .join(Indicator, Indicator.id == CampaignMember.indicator_id)
            .where(Indicator.value.ilike(pattern))
        )
        query = query.where(
            or_(
                Campaign.code.ilike(pattern),
                Campaign.display_name.ilike(pattern),
                Campaign.id.in_(matching_member_campaign_ids),
            )
        )

    summaries: list[CampaignSummary] = []
    for campaign in session.scalars(query.order_by(Campaign.code)):
        member_count = (
            session.scalar(
                select(func.count(CampaignMember.id)).where(
                    CampaignMember.campaign_id == campaign.id
                )
            )
            or 0
        )
        if member_count < min_size:
            continue
        summaries.append(
            CampaignSummary(
                code=campaign.code,
                display_name=campaign.display_name,
                status=campaign.status,
                score=campaign.score,
                member_count=member_count,
                relation_types=campaign.relation_types,
                first_seen=campaign.first_seen,
                last_seen=campaign.last_seen,
            )
        )
    return CampaignListResponse(campaigns=summaries, total=len(summaries))


@router.get("/{code}", response_model=CampaignDetail)
def get_campaign(code: str, session: Session = Depends(get_session)) -> CampaignDetail:
    campaign = get_campaign_or_404(session, code)
    return _build_campaign_detail(session, campaign)


@router.put("/{code}/display_name", response_model=CampaignDetail)
def update_display_name(
    code: str, body: DisplayNameUpdate, session: Session = Depends(get_session)
) -> CampaignDetail:
    campaign = get_campaign_or_404(session, code)
    campaign.display_name = body.display_name
    session.flush()
    return _build_campaign_detail(session, campaign)

