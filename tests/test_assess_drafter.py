"""Drafting: the LLM call is always mocked (a fake `AssessmentLLM.draft`
returning a canned dict, exactly the shape any real backend's adapter
would hand back), and every hard constraint from the milestone spec is
checked with a fixture that violates exactly one of them, a validation
failure must persist nothing."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ledgerhound.assess.attack import AttackDataset
from ledgerhound.assess.drafter import DraftBlockedError, DraftValidationError, draft_assessment
from ledgerhound.db.models import (
    AddressProfile,
    Assessment,
    Campaign,
    CampaignMember,
    Edge,
    EdgeRelation,
    Indicator,
    IndicatorType,
)

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


class _FakeLLM:
    """Stands in for any real `AssessmentLLM` adapter: `draft_assessment`
    only ever calls `.draft(...)` and uses whatever dict comes back, so a
    fake that just returns a canned dict exercises the exact same contract
    a real OpenAI-compatible (or any other) backend would fulfill."""

    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.calls = 0

    def draft(self, **_kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return self._response


def _valid_draft(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "key_judgements": [
            {
                "statement": "The two addresses share a receiving wallet.",
                "confidence": "high",
                "supporting_evidence_refs": [],
            }
        ],
        "summary": "A crypto scam campaign linked by a shared receiving wallet.",
        "targeting": {
            "victim_profile": "retail crypto users",
            "geographies": [],
            "impersonated_brands": [],
        },
        "ttps": [{"technique_id": "T1566", "technique_name": "Phishing", "observation": "..."}],
        "financial": {
            "narrative": "Funds moved through a shared wallet.",
            "total_observed_inflow": "150",
            "cashout_venues": [],
            "sanctions_exposure": "none observed",
        },
        "assessment": "Likely a single operator running both addresses.",
        "attribution": {"claim": None, "confidence": None, "rationale": "insufficient evidence"},
        "outlook": "Likely to continue using similar infrastructure.",
        "gaps": [],
    }
    base.update(overrides)
    return base


@pytest.fixture()
def campaign_with_evidence(db_session: Session) -> Campaign:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    campaign = _make_campaign(db_session, [a, b])
    db_session.add(
        Edge(
            src_indicator_id=a.id,
            dst_indicator_id=b.id,
            relation=EdgeRelation.SHARES_RECEIVING_WALLET,
            weight=1.0,
            evidence={"wallet": "0xW"},
        )
    )
    db_session.add(
        AddressProfile(
            indicator_id=a.id,
            chain="eth",
            decimals=18,
            provider="t",
            enriched_at=NOW,
            total_received=Decimal(100),
        )
    )
    db_session.add(
        AddressProfile(
            indicator_id=b.id,
            chain="eth",
            decimals=18,
            provider="t",
            enriched_at=NOW,
            total_received=Decimal(50),
        )
    )
    db_session.commit()
    return campaign


def _assessment_count(session: Session, campaign: Campaign) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(Assessment)
            .where(Assessment.campaign_id == campaign.id)
        )
        or 0
    )


def test_draft_assessment_persists_a_valid_draft(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    llm = _FakeLLM(_valid_draft())

    assessment = draft_assessment(
        db_session,
        campaign_with_evidence,
        llm=llm,
        model="test-model",
        attack_dataset=ATTACK_DATASET,
    )

    assert assessment.version == 1
    assert assessment.status == "draft"
    assert assessment.edited_by_human is False
    assert llm.calls == 1


def test_draft_blocked_when_evidence_unchanged(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    llm = _FakeLLM(_valid_draft())
    draft_assessment(
        db_session, campaign_with_evidence, llm=llm, model="m", attack_dataset=ATTACK_DATASET
    )

    with pytest.raises(DraftBlockedError):
        draft_assessment(
            db_session,
            campaign_with_evidence,
            llm=llm,
            model="m",
            attack_dataset=ATTACK_DATASET,
        )
    assert _assessment_count(db_session, campaign_with_evidence) == 1


def test_draft_force_redraft_creates_a_new_version(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    llm = _FakeLLM(_valid_draft())
    draft_assessment(
        db_session, campaign_with_evidence, llm=llm, model="m", attack_dataset=ATTACK_DATASET
    )

    second = draft_assessment(
        db_session,
        campaign_with_evidence,
        llm=llm,
        model="m",
        attack_dataset=ATTACK_DATASET,
        force=True,
    )
    assert second.version == 2


def test_draft_rejects_unresolvable_evidence_ref(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    bad = _valid_draft(
        key_judgements=[
            {
                "statement": "x",
                "confidence": "high",
                "supporting_evidence_refs": ["member:00000000-0000-0000-0000-000000000000"],
            }
        ]
    )
    llm = _FakeLLM(bad)

    with pytest.raises(DraftValidationError) as exc_info:
        draft_assessment(
            db_session,
            campaign_with_evidence,
            llm=llm,
            model="m",
            attack_dataset=ATTACK_DATASET,
        )
    assert any("unresolvable" in e for e in exc_info.value.errors)
    assert _assessment_count(db_session, campaign_with_evidence) == 0


def test_draft_rejects_unknown_attack_technique_id(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    bad = _valid_draft(
        ttps=[{"technique_id": "T0000", "technique_name": "Made Up", "observation": "..."}]
    )
    llm = _FakeLLM(bad)

    with pytest.raises(DraftValidationError) as exc_info:
        draft_assessment(
            db_session,
            campaign_with_evidence,
            llm=llm,
            model="m",
            attack_dataset=ATTACK_DATASET,
        )
    assert any("ATT&CK" in e for e in exc_info.value.errors)
    assert _assessment_count(db_session, campaign_with_evidence) == 0


def test_draft_rejects_attribution_without_high_confidence_support(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    bad = _valid_draft(
        key_judgements=[
            {"statement": "x", "confidence": "moderate", "supporting_evidence_refs": []}
        ],
        attribution={"claim": "Some Actor Group", "confidence": "moderate", "rationale": "..."},
    )
    llm = _FakeLLM(bad)

    with pytest.raises(DraftValidationError) as exc_info:
        draft_assessment(
            db_session,
            campaign_with_evidence,
            llm=llm,
            model="m",
            attack_dataset=ATTACK_DATASET,
        )
    assert any("attribution.claim" in e for e in exc_info.value.errors)
    assert _assessment_count(db_session, campaign_with_evidence) == 0


def test_draft_rejects_wrong_confidence_vocabulary(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    bad = _valid_draft(
        key_judgements=[{"statement": "x", "confidence": "likely", "supporting_evidence_refs": []}]
    )
    llm = _FakeLLM(bad)

    with pytest.raises(DraftValidationError):
        draft_assessment(
            db_session,
            campaign_with_evidence,
            llm=llm,
            model="m",
            attack_dataset=ATTACK_DATASET,
        )
    assert _assessment_count(db_session, campaign_with_evidence) == 0


def test_draft_rejects_mismatched_inflow_total(
    db_session: Session, campaign_with_evidence: Campaign
) -> None:
    financial = _valid_draft()["financial"]
    financial["total_observed_inflow"] = "999"
    bad = _valid_draft(financial=financial)
    llm = _FakeLLM(bad)

    with pytest.raises(DraftValidationError) as exc_info:
        draft_assessment(
            db_session,
            campaign_with_evidence,
            llm=llm,
            model="m",
            attack_dataset=ATTACK_DATASET,
        )
    assert any("does not match" in e for e in exc_info.value.errors)
    assert _assessment_count(db_session, campaign_with_evidence) == 0

