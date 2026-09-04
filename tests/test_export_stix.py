"""STIX bundle building: real `stix2-validator` validation, byte-for-byte
determinism, and the never-invent-an-ATT&CK-id hard rule.

Validation relies on `conftest.py`'s self-heal of the `stix2-validator`
PyPI package's missing bundled schemas — no `schema_dir` needs passing
here since that fix places the vendored schemas at the exact path the
library looks for by default.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.orm import Session
from stix2validator import ValidationOptions, validate_parsed_json

from ledgerhound.assess.attack import AttackDataset
from ledgerhound.assess.evidence import build_evidence_pack
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
from ledgerhound.export.stix import StixExportError, build_campaign_bundle, serialize_bundle

NOW = datetime(2026, 1, 1, tzinfo=UTC)
ATTACK_DATASET = AttackDataset(
    version="19.2",
    techniques={"T1566": "Phishing"},
    stix_ids={"T1566": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"},
)


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


def _valid_draft(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "key_judgements": [
            {"statement": "x", "confidence": "high", "supporting_evidence_refs": []}
        ],
        "summary": "A crypto scam campaign impersonating a fake exchange.",
        "targeting": {"victim_profile": "v", "geographies": [], "impersonated_brands": []},
        "ttps": [{"technique_id": "T1566", "technique_name": "Phishing", "observation": "o"}],
        "financial": {
            "narrative": "n",
            "total_observed_inflow": "100",
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


@pytest.fixture()
def campaign_bundle_inputs(
    db_session: Session,
) -> tuple[Campaign, Assessment, Any]:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.DOMAIN, "evil.example")
    campaign = _make_campaign(db_session, [a, b])
    db_session.add(
        Edge(
            src_indicator_id=a.id,
            dst_indicator_id=b.id,
            relation=EdgeRelation.SHARES_REGISTRAR_AND_NS,
            weight=0.2,
            evidence={},
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
    db_session.commit()

    assessment = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash="h",
        prompt_version="v1",
        model="m",
        draft=_valid_draft(),
        status="approved",
        reviewed_by="alice",
        reviewed_at=NOW,
        stale=False,
    )
    db_session.add(assessment)
    db_session.commit()

    pack = build_evidence_pack(db_session, campaign)
    return campaign, assessment, pack


def test_bundle_validates_with_stix2_validator(
    campaign_bundle_inputs: tuple[Campaign, Assessment, Any],
) -> None:
    campaign, assessment, pack = campaign_bundle_inputs
    bundle = build_campaign_bundle(campaign, assessment, pack, attack_dataset=ATTACK_DATASET)

    options = ValidationOptions(version="2.1")
    results = validate_parsed_json(bundle, options)
    assert results.is_valid, results.errors


def test_bundle_is_byte_for_byte_deterministic(
    campaign_bundle_inputs: tuple[Campaign, Assessment, Any],
) -> None:
    campaign, assessment, pack = campaign_bundle_inputs
    bundle1 = build_campaign_bundle(campaign, assessment, pack, attack_dataset=ATTACK_DATASET)
    bundle2 = build_campaign_bundle(campaign, assessment, pack, attack_dataset=ATTACK_DATASET)
    assert serialize_bundle(bundle1) == serialize_bundle(bundle2)


def test_bundle_refuses_to_invent_an_attack_pattern_id(
    campaign_bundle_inputs: tuple[Campaign, Assessment, Any],
) -> None:
    campaign, assessment, pack = campaign_bundle_inputs
    empty_dataset = AttackDataset(version="19.2", techniques={}, stix_ids={})
    with pytest.raises(StixExportError):
        build_campaign_bundle(campaign, assessment, pack, attack_dataset=empty_dataset)


def test_bundle_contains_expected_object_types(
    campaign_bundle_inputs: tuple[Campaign, Assessment, Any],
) -> None:
    campaign, assessment, pack = campaign_bundle_inputs
    bundle = build_campaign_bundle(campaign, assessment, pack, attack_dataset=ATTACK_DATASET)
    types = {obj["type"] for obj in bundle["objects"]}
    assert types == {
        "identity",
        "extension-definition",
        "marking-definition",
        "campaign",
        "indicator",
        "relationship",
        "attack-pattern",
        "report",
    }
