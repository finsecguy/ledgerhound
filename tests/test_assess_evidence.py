"""Evidence pack determinism, ref resolution, and the computed inflow
total `drafter.py` checks a draft's arithmetic against; plus staleness
flagging on a since-approved version when evidence changes."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy.orm import Session

from ledgerhound.assess.evidence import build_evidence_pack, refresh_staleness
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


def test_evidence_pack_is_deterministic_and_computes_inflow(db_session: Session) -> None:
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

    pack1 = build_evidence_pack(db_session, campaign)
    pack2 = build_evidence_pack(db_session, campaign)

    assert pack1.evidence_hash == pack2.evidence_hash
    assert pack1.total_observed_inflow == "150"
    assert f"member:{a.id}" in pack1.all_refs()
    assert any(e.relation == "shares_receiving_wallet" for e in pack1.edges)


def test_evidence_pack_hash_changes_when_data_changes(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    campaign = _make_campaign(db_session, [a, b])
    db_session.commit()
    pack_before = build_evidence_pack(db_session, campaign)

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
    pack_after = build_evidence_pack(db_session, campaign)

    assert pack_before.evidence_hash != pack_after.evidence_hash


def test_refresh_staleness_flags_approved_version_on_evidence_change(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    campaign = _make_campaign(db_session, [a, b])
    pack1 = build_evidence_pack(db_session, campaign)
    approved = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash=pack1.evidence_hash,
        prompt_version="v1",
        model="test-model",
        draft={},
        status="approved",
        stale=False,
    )
    db_session.add(approved)
    db_session.commit()

    refresh_staleness(db_session, campaign.id, pack1.evidence_hash)
    assert approved.stale is False

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
    pack2 = build_evidence_pack(db_session, campaign)

    refresh_staleness(db_session, campaign.id, pack2.evidence_hash)
    assert approved.stale is True
