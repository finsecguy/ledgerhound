"""Graph construction, scoring, and campaign persistence: exchange/mixer
nodes never appear in the graph, a registrar-only component is discarded,
stable identity across runs, merge/split event recording, and dry-run
persisting nothing."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ledgerhound.cluster.campaigns import run_clustering
from ledgerhound.cluster.config import ClusteringConfig
from ledgerhound.cluster.graph import build_graph
from ledgerhound.cluster.relations.base import LabelIndex
from ledgerhound.db.models import (
    AddressCounterparty,
    AddressProfile,
    Campaign,
    CampaignEvent,
    CampaignMember,
    DomainProfile,
    Edge,
    Indicator,
    IndicatorType,
)
from ledgerhound.enrich.labels.known import KnownAddressIndex

NOW = datetime(2026, 1, 1, tzinfo=UTC)
MIXER_ADDRESS = "0x722122dF12D4e14e13Ac3b6895a86e84145b6967"


def _make_indicator(session: Session, itype: IndicatorType, value: str) -> Indicator:
    ind = Indicator(type=itype, value=value, defanged_value=value, first_seen=NOW, last_seen=NOW)
    session.add(ind)
    session.flush()
    return ind


def _link_via_wallet(session: Session, a: Indicator, b: Indicator, wallet: str) -> None:
    for ind in (a, b):
        existing = session.scalar(
            select(AddressProfile).where(AddressProfile.indicator_id == ind.id)
        )
        if existing is None:
            session.add(
                AddressProfile(
                    indicator_id=ind.id, chain="eth", decimals=18, provider="t", enriched_at=NOW
                )
            )
        session.add(
            AddressCounterparty(
                indicator_id=ind.id,
                counterparty_address=wallet,
                direction="out",
                tx_count=1,
                total_value=Decimal(1),
            )
        )
    # This test session (like production) runs with autoflush=False
    # without this, a second call for the same indicator wouldn't see the
    # first call's pending (unflushed) AddressProfile insert and would
    # try to insert a duplicate.
    session.flush()


# --- graph exclusion -----------------------------------------------------


def test_exchange_mixer_addresses_never_appear_as_graph_nodes(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _link_via_wallet(db_session, a, b, MIXER_ADDRESS)
    db_session.commit()

    config = ClusteringConfig()
    label_index = LabelIndex(ofac=None, known=KnownAddressIndex.load())
    run_clustering(db_session, config, label_index=label_index)

    graph = build_graph(db_session)
    node_values = set()
    for node_id in graph.nodes:
        ind = db_session.scalar(select(Indicator).where(Indicator.id == node_id))
        if ind is not None:
            node_values.add(ind.value)
    assert MIXER_ADDRESS not in node_values
    # And since the only possible edge was excluded, no edges at all exist.
    assert graph.number_of_edges() == 0


# --- registrar-only discard ------------------------------------------------


def test_registrar_only_component_never_becomes_a_campaign(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    db_session.add(
        DomainProfile(
            indicator_id=d1.id, registrar="GoDaddy", ns_records=["ns1", "ns2"], enriched_at=NOW
        )
    )
    db_session.add(
        DomainProfile(
            indicator_id=d2.id, registrar="GoDaddy", ns_records=["ns1", "ns2"], enriched_at=NOW
        )
    )
    db_session.commit()

    config = ClusteringConfig()
    result = run_clustering(db_session, config)

    assert result.edges_added == 1  # the registrar/NS edge is real and gets persisted...
    assert result.campaigns_created == 0  # ...but never forms a campaign on its own
    assert list(db_session.scalars(select(Campaign))) == []


# --- stable identity, merge, split, dry-run ------------------------------


def test_same_input_across_two_runs_yields_same_campaign_ids(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _link_via_wallet(db_session, a, b, "0xW1")
    db_session.commit()

    config = ClusteringConfig()
    run_clustering(db_session, config)
    first_codes = sorted(c.code for c in db_session.scalars(select(Campaign)))

    run_clustering(db_session, config)
    second_codes = sorted(c.code for c in db_session.scalars(select(Campaign)))

    assert first_codes == second_codes
    assert len(first_codes) == 1


def test_merge_produces_a_merge_event_with_correct_before_after(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    c = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xC")
    d = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xD")
    _link_via_wallet(db_session, a, b, "0xW1")
    _link_via_wallet(db_session, c, d, "0xW2")
    db_session.commit()

    config = ClusteringConfig()
    run_clustering(db_session, config)
    campaigns_before = {c.code: c.id for c in db_session.scalars(select(Campaign))}
    assert len(campaigns_before) == 2

    # Bridge the two pairs -> one 4-node component -> a merge.
    _link_via_wallet(db_session, b, c, "0xBRIDGE")
    db_session.commit()

    result = run_clustering(db_session, config)
    assert result.campaigns_merged == 1
    assert result.campaigns_created == 0

    campaigns_after = list(db_session.scalars(select(Campaign)))
    assert len(campaigns_after) == 2  # survivor + absorbed row, both still exist
    survivor = next(c for c in campaigns_after if c.code in campaigns_before)
    all_members = list(
        db_session.scalars(select(CampaignMember).where(CampaignMember.campaign_id == survivor.id))
    )
    assert len(all_members) == 4  # survivor absorbed all four members

    events = list(db_session.scalars(select(CampaignEvent)))
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "merge"
    assert event.campaign_id == survivor.id
    assert len(event.members_before) == 2
    assert len(event.members_after) == 4


def test_split_produces_a_split_event_with_correct_before_after(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    c = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xC")
    d = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xD")
    _link_via_wallet(db_session, a, b, "0xW1")
    _link_via_wallet(db_session, b, c, "0xBRIDGE")
    _link_via_wallet(db_session, c, d, "0xW2")
    db_session.commit()

    config = ClusteringConfig()
    run_clustering(db_session, config)
    campaigns_before = list(db_session.scalars(select(Campaign)))
    assert len(campaigns_before) == 1
    original_code = campaigns_before[0].code

    # Remove the bridge -> splits back into {A,B} and {C,D}.
    db_session.execute(
        delete(AddressCounterparty).where(AddressCounterparty.counterparty_address == "0xBRIDGE")
    )
    db_session.commit()

    result = run_clustering(db_session, config)
    assert result.campaigns_split == 1
    assert result.campaigns_created == 1

    campaigns_after = list(db_session.scalars(select(Campaign)))
    assert len(campaigns_after) == 2
    assert original_code in {c.code for c in campaigns_after}  # continuing id survives

    events = list(db_session.scalars(select(CampaignEvent)))
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "split"
    assert len(event.members_before) == 4
    assert len(event.members_after) == 2
    assert len(event.related_campaign_codes) == 1


def test_dry_run_persists_nothing(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    _link_via_wallet(db_session, a, b, "0xW1")
    db_session.commit()

    config = ClusteringConfig()
    result = run_clustering(db_session, config, dry_run=True)

    assert result.dry_run is True
    assert result.campaigns_created == 1  # reported, but not persisted
    assert list(db_session.scalars(select(Campaign))) == []
    assert list(db_session.scalars(select(Edge))) == []


def test_determinism_same_state_same_edge_set(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    c = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xC")
    _link_via_wallet(db_session, a, b, "0xW1")
    _link_via_wallet(db_session, b, c, "0xW2")
    db_session.commit()

    config = ClusteringConfig()
    run_clustering(db_session, config)
    edges_first = sorted(
        (e.src_indicator_id, e.dst_indicator_id, e.relation, e.weight)
        for e in db_session.scalars(select(Edge))
    )

    run_clustering(db_session, config)
    edges_second = sorted(
        (e.src_indicator_id, e.dst_indicator_id, e.relation, e.weight)
        for e in db_session.scalars(select(Edge))
    )

    assert edges_first == edges_second

