"""The publish/export gate: only an approved, non-stale assessment makes
a campaign publishable — everything else (`lh export ...`, `lh publish`)
delegates the decision here."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy.orm import Session

from ledgerhound.assess.evidence import build_evidence_pack
from ledgerhound.db.models import (
    AddressProfile,
    Assessment,
    Campaign,
    CampaignMember,
    Indicator,
    IndicatorType,
)
from ledgerhound.export.gate import (
    NotPublishableError,
    get_publishable_assessment,
    list_publishable_campaigns,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _make_indicator(session: Session, itype: IndicatorType, value: str) -> Indicator:
    ind = Indicator(type=itype, value=value, defanged_value=value, first_seen=NOW, last_seen=NOW)
    session.add(ind)
    session.flush()
    return ind


def _make_campaign(session: Session, code: str, members: list[Indicator]) -> Campaign:
    campaign = Campaign(
        code=code,
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


def test_refuses_a_campaign_with_no_approved_assessment(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    campaign = _make_campaign(db_session, "LH-2026-001", [a])
    db_session.commit()

    with pytest.raises(NotPublishableError, match="no approved assessment"):
        get_publishable_assessment(db_session, campaign)


def test_refuses_a_stale_approved_assessment(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    campaign = _make_campaign(db_session, "LH-2026-001", [a])
    db_session.commit()

    pack = build_evidence_pack(db_session, campaign)
    approved = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash=pack.evidence_hash,
        prompt_version="v1",
        model="m",
        draft={},
        status="approved",
        reviewed_by="alice",
        reviewed_at=NOW,
        stale=False,
    )
    db_session.add(approved)
    db_session.commit()

    # Evidence changes after approval; the gate must catch this on its
    # own even though nothing called `lh assess draft` again to notice.
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

    with pytest.raises(NotPublishableError, match="stale"):
        get_publishable_assessment(db_session, campaign)
    assert approved.stale is True


def test_allows_an_approved_fresh_assessment(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    campaign = _make_campaign(db_session, "LH-2026-001", [a])
    db_session.commit()

    pack_before = build_evidence_pack(db_session, campaign)
    approved = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash=pack_before.evidence_hash,
        prompt_version="v1",
        model="m",
        draft={},
        status="approved",
        reviewed_by="alice",
        reviewed_at=NOW,
        stale=False,
    )
    db_session.add(approved)
    db_session.commit()

    assessment, pack = get_publishable_assessment(db_session, campaign)
    assert assessment.id == approved.id
    assert pack.evidence_hash == pack_before.evidence_hash


def test_list_publishable_campaigns_skips_unapproved(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    publishable = _make_campaign(db_session, "LH-2026-001", [a])
    unapproved = _make_campaign(db_session, "LH-2026-002", [b])
    db_session.commit()

    pack = build_evidence_pack(db_session, publishable)
    db_session.add(
        Assessment(
            campaign_id=publishable.id,
            version=1,
            evidence_hash=pack.evidence_hash,
            prompt_version="v1",
            model="m",
            draft={},
            status="approved",
            reviewed_by="alice",
            reviewed_at=NOW,
            stale=False,
        )
    )
    db_session.commit()

    results = list_publishable_campaigns(db_session)
    codes = {c.code for c, _a, _p in results}
    assert codes == {"LH-2026-001"}
    assert unapproved.code not in codes
