"""Assessment endpoints: the dashboard equivalent of every `lh assess`
CLI test in `test_assess_drafter.py`/`test_assess_review.py`, same
rejected cases (bad refs, unknown ATT&CK ids, attribution without
support, wrong confidence vocabulary, inflow mismatch), same state
machine, same stale-flag surfacing, because the API calls the exact
same `assess/` functions, not a re-implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from ledgerhound.db.models import Assessment, Campaign, CampaignMember, Indicator, IndicatorType

NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _attack_cache_for_edits(attack_cache: Any) -> None:
    """Every edit/draft endpoint in this file needs a resolvable ATT&CK
    cache (see the `attack_cache` fixture) even for drafts with no
    `ttps`, the API loads it unconditionally, matching `lh assess edit`."""


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


def _valid_draft(total_observed_inflow: str = "0", **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
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
    base.update(overrides)
    return base


def _seed_campaign_with_draft(session: Session) -> tuple[Campaign, Assessment]:
    a = _make_indicator(session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(session, IndicatorType.ETH_ADDRESS, "0xB")
    campaign = _make_campaign(session, [a, b])
    assessment = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash="h",
        prompt_version="v1",
        model="test-model",
        draft=_valid_draft(),
        status="draft",
        stale=False,
    )
    session.add(assessment)
    session.commit()
    return campaign, assessment


def test_get_assessment_defaults_to_latest_version(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, assessment = _seed_campaign_with_draft(db_session)
    response = api_client.get(f"/api/campaigns/{campaign.code}/assessment")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == 1
    assert body["draft"]["summary"] == "s"
    # ref descriptions are expanded, not raw evidence-pack JSON.
    assert isinstance(body["evidence_ref_descriptions"], dict)


def test_get_assessment_404_for_unknown_version(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    response = api_client.get(f"/api/campaigns/{campaign.code}/assessment", params={"version": 99})
    assert response.status_code == 404


def test_list_assessment_versions(db_session: Session, api_client: TestClient) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    response = api_client.get(f"/api/campaigns/{campaign.code}/assessment/versions")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["version"] == 1


def test_edit_rejects_unresolvable_evidence_ref(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    bad = _valid_draft(
        key_judgements=[
            {
                "statement": "x",
                "confidence": "high",
                "supporting_evidence_refs": ["member:00000000-0000-0000-0000-000000000000"],
            }
        ]
    )
    response = api_client.put(f"/api/campaigns/{campaign.code}/assessment/1", json=bad)
    assert response.status_code == 422
    assert any("unresolvable" in e for e in response.json()["detail"]["errors"])


def test_edit_rejects_unknown_attack_technique_id(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    bad = _valid_draft(
        ttps=[{"technique_id": "T0000", "technique_name": "Made Up", "observation": "..."}]
    )
    response = api_client.put(f"/api/campaigns/{campaign.code}/assessment/1", json=bad)
    assert response.status_code == 422
    assert any("ATT&CK" in e for e in response.json()["detail"]["errors"])


def test_edit_rejects_attribution_without_high_confidence_support(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    bad = _valid_draft(
        key_judgements=[
            {"statement": "x", "confidence": "moderate", "supporting_evidence_refs": []}
        ],
        attribution={"claim": "Some Actor Group", "confidence": "moderate", "rationale": "..."},
    )
    response = api_client.put(f"/api/campaigns/{campaign.code}/assessment/1", json=bad)
    assert response.status_code == 422
    assert any("attribution.claim" in e for e in response.json()["detail"]["errors"])


def test_edit_rejects_wrong_confidence_vocabulary_at_schema_level(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    bad = _valid_draft(
        key_judgements=[{"statement": "x", "confidence": "likely", "supporting_evidence_refs": []}]
    )
    response = api_client.put(f"/api/campaigns/{campaign.code}/assessment/1", json=bad)
    # Caught by pydantic/FastAPI's own schema validation (Literal enum),
    # before the handler even runs -- a field-level error, not a 500.
    assert response.status_code == 422


def test_edit_rejects_mismatched_inflow_total(db_session: Session, api_client: TestClient) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    bad = _valid_draft(total_observed_inflow="0")
    bad["financial"]["total_observed_inflow"] = "999"
    response = api_client.put(f"/api/campaigns/{campaign.code}/assessment/1", json=bad)
    assert response.status_code == 422
    assert any("does not match" in e for e in response.json()["detail"]["errors"])


def test_edit_valid_draft_creates_new_version_marked_edited_by_human(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    edited = _valid_draft()
    edited["summary"] = "edited via dashboard"
    response = api_client.put(f"/api/campaigns/{campaign.code}/assessment/1", json=edited)
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == 2
    assert body["edited_by_human"] is True
    assert body["status"] == "in_review"
    assert body["draft"]["summary"] == "edited via dashboard"


def test_approve_then_reapprove_is_illegal(db_session: Session, api_client: TestClient) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    response = api_client.post(
        f"/api/campaigns/{campaign.code}/assessment/1/approve",
        json={"notes": "ok", "reviewer": "alice"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"

    response = api_client.post(
        f"/api/campaigns/{campaign.code}/assessment/1/approve", json={"notes": "again"}
    )
    assert response.status_code == 409


def test_approve_a_rejected_version_is_illegal(db_session: Session, api_client: TestClient) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    api_client.post(f"/api/campaigns/{campaign.code}/assessment/1/reject", json={"notes": "no"})

    response = api_client.post(
        f"/api/campaigns/{campaign.code}/assessment/1/approve", json={"notes": "ok"}
    )
    assert response.status_code == 409


def test_reject_already_rejected_is_illegal(db_session: Session, api_client: TestClient) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    api_client.post(f"/api/campaigns/{campaign.code}/assessment/1/reject", json={"notes": "no"})

    response = api_client.post(
        f"/api/campaigns/{campaign.code}/assessment/1/reject", json={"notes": "again"}
    )
    assert response.status_code == 409


def test_exactly_one_approved_version_requires_force(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    api_client.post(f"/api/campaigns/{campaign.code}/assessment/1/approve", json={"notes": "ok"})

    second = Assessment(
        campaign_id=campaign.id,
        version=2,
        evidence_hash="h2",
        prompt_version="v1",
        model="test-model",
        draft=_valid_draft(),
        status="draft",
        stale=False,
    )
    db_session.add(second)
    db_session.commit()

    response = api_client.post(
        f"/api/campaigns/{campaign.code}/assessment/2/approve", json={"notes": "ok"}
    )
    assert response.status_code == 409

    response = api_client.post(
        f"/api/campaigns/{campaign.code}/assessment/2/approve",
        json={"notes": "ok", "force": True},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"


def test_diff_returns_both_drafts_and_unified_diff(
    db_session: Session, api_client: TestClient
) -> None:
    campaign, _assessment = _seed_campaign_with_draft(db_session)
    edited = _valid_draft()
    edited["summary"] = "a different summary"
    edit_response = api_client.put(f"/api/campaigns/{campaign.code}/assessment/1", json=edited)
    assert edit_response.status_code == 200

    response = api_client.get(
        f"/api/campaigns/{campaign.code}/assessment/diff", params={"from": 1, "to": 2}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["draft_a"]["summary"] == "s"
    assert body["draft_b"]["summary"] == "a different summary"
    assert "a different summary" in body["unified_diff"]


def test_stale_flag_is_surfaced_on_the_assessment(
    db_session: Session, api_client: TestClient
) -> None:
    from decimal import Decimal

    from ledgerhound.assess.evidence import build_evidence_pack
    from ledgerhound.db.models import AddressProfile

    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    campaign = _make_campaign(db_session, [a])
    pack = build_evidence_pack(db_session, campaign)
    approved = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash=pack.evidence_hash,
        prompt_version="v1",
        model="m",
        draft=_valid_draft(),
        status="approved",
        reviewed_by="alice",
        reviewed_at=NOW,
        stale=False,
    )
    db_session.add(approved)
    db_session.commit()

    response = api_client.get(f"/api/campaigns/{campaign.code}/assessment")
    assert response.json()["stale"] is False

    # Change the evidence without re-drafting.
    db_session.add(
        AddressProfile(
            indicator_id=a.id,
            chain="eth",
            decimals=18,
            provider="t",
            enriched_at=NOW,
            total_received=Decimal(5),
        )
    )
    db_session.commit()

    # A GET alone doesn't refresh staleness (no write happens for a
    # read); an edit does, as a side effect of rebuilding the evidence
    # pack before validating -- exactly like `lh assess edit`/`draft`.
    # The fresh pack's computed inflow is now "5" (the AddressProfile
    # just added above), so the edit must match that, not the original.
    edit_response = api_client.put(
        f"/api/campaigns/{campaign.code}/assessment/1", json=_valid_draft(total_observed_inflow="5")
    )
    assert edit_response.status_code == 200

    response = api_client.get(f"/api/campaigns/{campaign.code}/assessment", params={"version": 1})
    assert response.json()["stale"] is True

