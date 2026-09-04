"""Campaigns and graph endpoints: list/detail shapes, filtering/search,
display-name rename, and the graph/explain endpoints — all presentational
reads over data seeded directly via `db_session`."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from ledgerhound.db.models import (
    AddressProfile,
    Campaign,
    CampaignEvent,
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


def _make_campaign(
    session: Session, code: str, members: list[Indicator], *, status: str = "active"
) -> Campaign:
    campaign = Campaign(
        code=code,
        status=status,
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


def test_list_campaigns_shape(db_session: Session, api_client: TestClient) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _make_campaign(db_session, "LH-2026-001", [a, b])
    db_session.commit()

    response = api_client.get("/api/campaigns")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["campaigns"][0]["code"] == "LH-2026-001"
    assert body["campaigns"][0]["member_count"] == 2


def test_list_campaigns_filters_by_status(db_session: Session, api_client: TestClient) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _make_campaign(db_session, "LH-2026-001", [a], status="active")
    _make_campaign(db_session, "LH-2026-002", [b], status="dormant")
    db_session.commit()

    response = api_client.get("/api/campaigns", params={"status": "dormant"})
    assert response.status_code == 200
    codes = {c["code"] for c in response.json()["campaigns"]}
    assert codes == {"LH-2026-002"}


def test_list_campaigns_rejects_invalid_status(db_session: Session, api_client: TestClient) -> None:
    response = api_client.get("/api/campaigns", params={"status": "bogus"})
    assert response.status_code == 400


def test_list_campaigns_filters_by_min_size(db_session: Session, api_client: TestClient) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _make_campaign(db_session, "LH-2026-001", [a])
    _make_campaign(db_session, "LH-2026-002", [a, b])
    db_session.commit()

    response = api_client.get("/api/campaigns", params={"min_size": 2})
    codes = {c["code"] for c in response.json()["campaigns"]}
    assert codes == {"LH-2026-002"}


def test_list_campaigns_search_matches_member_value(
    db_session: Session, api_client: TestClient
) -> None:
    a = _make_indicator(db_session, IndicatorType.DOMAIN, "evil-exchange.example")
    b = _make_indicator(db_session, IndicatorType.DOMAIN, "unrelated.example")
    _make_campaign(db_session, "LH-2026-001", [a])
    _make_campaign(db_session, "LH-2026-002", [b])
    db_session.commit()

    response = api_client.get("/api/campaigns", params={"search": "evil-exchange"})
    codes = {c["code"] for c in response.json()["campaigns"]}
    assert codes == {"LH-2026-001"}


def test_get_campaign_detail_includes_members_and_events(
    db_session: Session, api_client: TestClient
) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    campaign = _make_campaign(db_session, "LH-2026-001", [a, b])
    db_session.add(
        CampaignEvent(
            campaign_id=campaign.id,
            event_type="merge",
            occurred_at=NOW,
            related_campaign_codes=["LH-2026-002"],
            members_before=[str(a.id)],
            members_after=[str(a.id), str(b.id)],
        )
    )
    db_session.commit()

    response = api_client.get("/api/campaigns/LH-2026-001")
    assert response.status_code == 200
    body = response.json()
    assert {m["value"] for m in body["members"]} == {"0xA", "0xB"}
    assert len(body["events"]) == 1
    assert body["events"][0]["event_type"] == "merge"
    assert body["events"][0]["members_after_count"] == 2
    assert body["latest_assessment"] is None


def test_get_campaign_detail_404_for_unknown_code(
    db_session: Session, api_client: TestClient
) -> None:
    response = api_client.get("/api/campaigns/LH-9999-999")
    assert response.status_code == 404


def test_update_display_name(db_session: Session, api_client: TestClient) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    _make_campaign(db_session, "LH-2026-001", [a])
    db_session.commit()

    response = api_client.put(
        "/api/campaigns/LH-2026-001/display_name", json={"display_name": "Fake Exchange Ring"}
    )
    assert response.status_code == 200
    assert response.json()["display_name"] == "Fake Exchange Ring"

    # Persisted, not just echoed back.
    response = api_client.get("/api/campaigns/LH-2026-001")
    assert response.json()["display_name"] == "Fake Exchange Ring"


def test_campaign_graph_reflects_members_and_edges(
    db_session: Session, api_client: TestClient
) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _make_campaign(db_session, "LH-2026-001", [a, b])
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
    db_session.commit()

    response = api_client.get("/api/campaigns/LH-2026-001/graph")
    assert response.status_code == 200
    body = response.json()
    assert len(body["nodes"]) == 2
    assert len(body["edges"]) == 1
    assert body["edges"][0]["relation"] == "shares_receiving_wallet"
    assert body["edges"][0]["evidence"] == {"wallet": "0xW"}


def test_explain_returns_direct_edges(db_session: Session, api_client: TestClient) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _make_campaign(db_session, "LH-2026-001", [a, b])
    db_session.add(
        Edge(
            src_indicator_id=a.id,
            dst_indicator_id=b.id,
            relation=EdgeRelation.SHARES_RECEIVING_WALLET,
            weight=1.0,
            evidence={"wallet": "0xW"},
        )
    )
    db_session.commit()

    response = api_client.get(f"/api/campaigns/LH-2026-001/explain/{a.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["indicator_value"] == "0xA"
    assert len(body["direct_edges"]) == 1
    assert body["direct_edges"][0]["neighbor_value"] == "0xB"


def test_explain_404_for_indicator_not_in_campaign(
    db_session: Session, api_client: TestClient
) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    outsider = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xC")
    _make_campaign(db_session, "LH-2026-001", [a])
    db_session.commit()

    response = api_client.get(f"/api/campaigns/LH-2026-001/explain/{outsider.id}")
    assert response.status_code == 404
