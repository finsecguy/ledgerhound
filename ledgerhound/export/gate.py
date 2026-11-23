"""The one rule every export/report/publish path shares: only a campaign
with an approved, non-stale assessment can be exported or published.

Staleness is re-checked here against a freshly built evidence pack
rather than trusting whatever `Assessment.stale` last recorded. Nothing
guarantees `lh assess draft`/`edit` (the only two things that normally
refresh it) ran again after the campaign's evidence last changed, so an
export/publish attempt always gets the current, authoritative answer.
Rebuilding the pack is pure DB reads, not a network call, so it doesn't
violate this package's no-network rule.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.assess.evidence import EvidencePack, build_evidence_pack, refresh_staleness
from ledgerhound.db.models import Assessment, Campaign


class NotPublishableError(Exception):
    """Raised when a campaign has no approved assessment, or its approved
    assessment is stale relative to the campaign's current evidence."""


def get_publishable_assessment(
    session: Session, campaign: Campaign
) -> tuple[Assessment, EvidencePack]:
    approved = session.scalar(
        select(Assessment).where(
            Assessment.campaign_id == campaign.id, Assessment.status == "approved"
        )
    )
    if approved is None:
        raise NotPublishableError(f"{campaign.code} has no approved assessment.")

    pack = build_evidence_pack(session, campaign)
    refresh_staleness(session, campaign.id, pack.evidence_hash)
    if approved.stale:
        raise NotPublishableError(
            f"{campaign.code}'s approved assessment (v{approved.version}) is stale. "
            "its evidence has changed since approval. Re-draft and re-approve before "
            "publishing."
        )
    return approved, pack


def list_publishable_campaigns(session: Session) -> list[tuple[Campaign, Assessment, EvidencePack]]:
    """Every campaign with a currently-approved, non-stale assessment,
    sorted by code. Used by the "all campaigns" export commands
    (`lh export misp`, `lh export feed`, `lh publish --all`)."""
    results: list[tuple[Campaign, Assessment, EvidencePack]] = []
    for campaign in session.scalars(select(Campaign).order_by(Campaign.code)):
        try:
            assessment, pack = get_publishable_assessment(session, campaign)
        except NotPublishableError:
            continue
        results.append((campaign, assessment, pack))
    return results

