"""Review state machine (illegal transitions rejected), exactly-one-
approved-version enforcement, edit re-validation producing a new
version, and the version diff."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ledgerhound.assess.attack import AttackDataset
from ledgerhound.assess.drafter import DraftValidationError
from ledgerhound.assess.review import (
    AlreadyApprovedError,
    IllegalTransitionError,
    approve_assessment,
    edit_assessment,
    reject_assessment,
    render_diff,
)
from ledgerhound.db.models import Assessment, Campaign, CampaignMember, Indicator, IndicatorType

NOW = datetime(2026, 1, 1, tzinfo=UTC)
ATTACK_DATASET = AttackDataset(version="15.1", techniques={"T1566": "Phishing"})


def _make_indicator(session: Session, itype: IndicatorType, value: str) -> Indicator:
    ind = Indicator(type=itype, value=value, defanged_value=value, first_seen=NOW, last_seen=NOW)
    session.add(ind)
    session.flush()
    return ind


def _make_campaign(session: Session, members: list[Indicator]) -> Campaign:
    campaign = Campaign(
        code="LH-2026-001",
        status="active",
        score=1.0,
        relation_types=["shares_receiving_wallet"],
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(campaign)
    session.flush()
    for member in members:
        session.add(CampaignMember(campaign_id=campaign.id, indicator_id=member.id, joined_at=NOW))
    session.flush()
    return campaign


def _valid_draft(total_observed_inflow: str = "0") -> dict[str, Any]:
    return {
        "key_judgements": [
            {"statement": "x", "confidence": "high", "supporting_evidence_refs": []}
        ],
        "summary": "s",
        "targeting": {"victim_profile": "v", "geographies": [], "impersonated_brands": []},
        "ttps": [],
        "financial": {
            "narrative": "n",
            "total_observed_inflow": total_observed_inflow,
            "cashout_venues": [],
            "sanctions_exposure": "none",
        },
        "assessment": "a",
        "attribution": {"claim": None, "confidence": None, "rationale": "r"},
        "outlook": "o",
        "gaps": [],
    }


@pytest.fixture()
def campaign_with_draft(db_session: Session) -> tuple[Campaign, Assessment]:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    campaign = _make_campaign(db_session, [a, b])
    assessment = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash="hash1",
        prompt_version="v1",
        model="test-model",
        draft=_valid_draft(),
        status="draft",
        stale=False,
    )
    db_session.add(assessment)
    db_session.commit()
    return campaign, assessment


def test_approving_an_already_approved_version_is_illegal(
    db_session: Session, campaign_with_draft: tuple[Campaign, Assessment]
) -> None:
    campaign, _assessment = campaign_with_draft
    approve_assessment(db_session, campaign, version=1, reviewer="alice", notes="ok")

    with pytest.raises(IllegalTransitionError):
        approve_assessment(db_session, campaign, version=1, reviewer="alice", notes="again")


def test_approving_a_rejected_version_is_illegal(
    db_session: Session, campaign_with_draft: tuple[Campaign, Assessment]
) -> None:
    campaign, _assessment = campaign_with_draft
    reject_assessment(db_session, campaign, version=1, reviewer="alice", notes="no good")

    with pytest.raises(IllegalTransitionError):
        approve_assessment(db_session, campaign, version=1, reviewer="alice", notes="ok")


def test_rejecting_an_already_rejected_version_is_illegal(
    db_session: Session, campaign_with_draft: tuple[Campaign, Assessment]
) -> None:
    campaign, _assessment = campaign_with_draft
    reject_assessment(db_session, campaign, version=1, reviewer="alice", notes="no good")

    with pytest.raises(IllegalTransitionError):
        reject_assessment(db_session, campaign, version=1, reviewer="alice", notes="again")


def test_exactly_one_approved_version_per_campaign(
    db_session: Session, campaign_with_draft: tuple[Campaign, Assessment]
) -> None:
    campaign, _assessment = campaign_with_draft
    approve_assessment(db_session, campaign, version=1, reviewer="alice", notes="ok")

    second = Assessment(
        campaign_id=campaign.id,
        version=2,
        evidence_hash="hash2",
        prompt_version="v1",
        model="test-model",
        draft=_valid_draft(),
        status="draft",
        stale=False,
    )
    db_session.add(second)
    db_session.commit()

    with pytest.raises(AlreadyApprovedError):
        approve_assessment(db_session, campaign, version=2, reviewer="alice", notes="ok")

    approved = approve_assessment(
        db_session, campaign, version=2, reviewer="alice", notes="ok", force=True
    )
    assert approved.version == 2

    first_row = db_session.scalar(
        select(Assessment).where(Assessment.campaign_id == campaign.id, Assessment.version == 1)
    )
    assert first_row is not None
    assert first_row.status == "rejected"

    approved_rows = list(
        db_session.scalars(
            select(Assessment).where(
                Assessment.campaign_id == campaign.id, Assessment.status == "approved"
            )
        )
    )
    assert len(approved_rows) == 1


def test_edit_revalidates_and_creates_a_new_version(
    db_session: Session, campaign_with_draft: tuple[Campaign, Assessment]
) -> None:
    campaign, assessment = campaign_with_draft
    edited = _valid_draft()
    edited["summary"] = "edited summary"

    new_version = edit_assessment(
        db_session, campaign, assessment, edited, attack_dataset=ATTACK_DATASET
    )

    assert new_version.version == 2
    assert new_version.edited_by_human is True
    assert new_version.status == "in_review"
    assert new_version.draft["summary"] == "edited summary"


def test_edit_rejects_an_invalid_edited_draft_and_persists_nothing(
    db_session: Session, campaign_with_draft: tuple[Campaign, Assessment]
) -> None:
    campaign, assessment = campaign_with_draft
    edited = _valid_draft()
    edited["ttps"] = [{"technique_id": "T9999", "technique_name": "Fake", "observation": "x"}]

    with pytest.raises(DraftValidationError):
        edit_assessment(db_session, campaign, assessment, edited, attack_dataset=ATTACK_DATASET)

    count = db_session.scalar(
        select(func.count()).select_from(Assessment).where(Assessment.campaign_id == campaign.id)
    )
    assert count == 1


def test_render_diff_shows_the_changed_field(
    db_session: Session, campaign_with_draft: tuple[Campaign, Assessment]
) -> None:
    campaign, assessment = campaign_with_draft
    edited = _valid_draft()
    edited["summary"] = "a completely different summary"

    new_version = edit_assessment(
        db_session, campaign, assessment, edited, attack_dataset=ATTACK_DATASET
    )
    diff_text = render_diff(assessment, new_version)

    assert "a completely different summary" in diff_text
