"""Relation detector tests against fixture projection data: correct edges,
correct evidence, correct rejections (exchange/mixer exclusion, wildcard
cert discount, missing-data skips)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy.orm import Session

from ledgerhound.cluster.config import ClusteringConfig
from ledgerhound.cluster.relations.base import LabelIndex
from ledgerhound.cluster.relations.cashout import SharesCashoutPathRelation
from ledgerhound.cluster.relations.cert import SharesCertRelation
from ledgerhound.cluster.relations.registrar_ns import SharesRegistrarAndNsRelation
from ledgerhound.cluster.relations.template import SharesTemplateRelation
from ledgerhound.cluster.relations.wallet import SharesReceivingWalletRelation
from ledgerhound.db.models import (
    AddressCounterparty,
    AddressProfile,
    DomainCert,
    DomainProfile,
    Indicator,
    IndicatorType,
    Trace,
    TraceNodeRow,
)
from ledgerhound.enrich.labels.known import KnownAddressIndex

NOW = datetime(2026, 1, 1, tzinfo=UTC)

# A real Tornado Cash mixer address from the bundled known-addresses dataset.
MIXER_ADDRESS = "0x722122dF12D4e14e13Ac3b6895a86e84145b6967"


def _make_indicator(session: Session, itype: IndicatorType, value: str) -> Indicator:
    ind = Indicator(type=itype, value=value, defanged_value=value, first_seen=NOW, last_seen=NOW)
    session.add(ind)
    session.flush()
    return ind


def _config() -> ClusteringConfig:
    return ClusteringConfig()


def _real_label_index() -> LabelIndex:
    return LabelIndex(ofac=None, known=KnownAddressIndex.load())


# --- shares_receiving_wallet ------------------------------------------


def test_wallet_relation_links_indicators_sharing_a_counterparty(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    for ind in (a, b):
        db_session.add(
            AddressProfile(
                indicator_id=ind.id, chain="eth", decimals=18, provider="t", enriched_at=NOW
            )
        )
        db_session.add(
            AddressCounterparty(
                indicator_id=ind.id,
                counterparty_address="0xSHARED",
                direction="out",
                tx_count=1,
                total_value=Decimal(1),
            )
        )
    db_session.commit()

    edges = list(SharesReceivingWalletRelation(_config()).detect(db_session))

    assert len(edges) == 1
    edge = edges[0]
    assert {edge.src_indicator_id, edge.dst_indicator_id} == {a.id, b.id}
    assert edge.relation == "shares_receiving_wallet"
    assert edge.weight == 1.0
    assert edge.evidence["wallet"] == "0xSHARED"
    assert "src_raw_report_ids" in edge.evidence
    assert "dst_raw_report_ids" in edge.evidence


def test_wallet_relation_ignores_inbound_direction(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    for ind in (a, b):
        db_session.add(
            AddressProfile(
                indicator_id=ind.id, chain="eth", decimals=18, provider="t", enriched_at=NOW
            )
        )
        # direction="in" means the wallet paid *them*, not a shared payout.
        db_session.add(
            AddressCounterparty(
                indicator_id=ind.id,
                counterparty_address="0xSHARED",
                direction="in",
                tx_count=1,
                total_value=Decimal(1),
            )
        )
    db_session.commit()

    edges = list(SharesReceivingWalletRelation(_config()).detect(db_session))
    assert edges == []


def test_wallet_relation_excludes_mixer_as_linking_node(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xB")
    for ind in (a, b):
        db_session.add(
            AddressProfile(
                indicator_id=ind.id, chain="eth", decimals=18, provider="t", enriched_at=NOW
            )
        )
        db_session.add(
            AddressCounterparty(
                indicator_id=ind.id,
                counterparty_address=MIXER_ADDRESS,
                direction="out",
                tx_count=1,
                total_value=Decimal(1),
            )
        )
    db_session.commit()

    edges = list(
        SharesReceivingWalletRelation(_config(), label_index=_real_label_index()).detect(db_session)
    )
    assert edges == []  # two scams both paying a known mixer isn't evidence of a link


# --- shares_cashout_path ------------------------------------------------


def test_cashout_relation_links_roots_sharing_a_labeled_terminal(db_session: Session) -> None:
    root1 = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xR1")
    root2 = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xR2")
    t1 = Trace(root_indicator_id=root1.id, depth=2, run_at=NOW, truncated=False, summary={})
    t2 = Trace(root_indicator_id=root2.id, depth=2, run_at=NOW, truncated=False, summary={})
    db_session.add_all([t1, t2])
    db_session.flush()
    db_session.add(
        TraceNodeRow(
            trace_id=t1.id,
            address="0xEXCHANGE",
            hop=2,
            is_terminal=True,
            terminal_reason="exchange",
            labels=[],
        )
    )
    db_session.add(
        TraceNodeRow(
            trace_id=t2.id,
            address="0xEXCHANGE",
            hop=1,
            is_terminal=True,
            terminal_reason="exchange",
            labels=[],
        )
    )
    # A max_depth terminal must never count as a cashout path.
    db_session.add(
        TraceNodeRow(
            trace_id=t1.id,
            address="0xDEADEND",
            hop=2,
            is_terminal=True,
            terminal_reason="max_depth",
            labels=[],
        )
    )
    db_session.commit()

    edges = list(SharesCashoutPathRelation(_config()).detect(db_session))

    assert len(edges) == 1
    edge = edges[0]
    assert {edge.src_indicator_id, edge.dst_indicator_id} == {root1.id, root2.id}
    assert edge.evidence["terminal_address"] == "0xEXCHANGE"
    assert edge.evidence["terminal_label_type"] == "exchange"
    assert edge.evidence["hop_from_src"] in (1, 2)
    assert edge.evidence["hop_from_dst"] in (1, 2)


def test_cashout_relation_uses_only_the_latest_trace_per_root(db_session: Session) -> None:
    root1 = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xR1")
    root2 = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xR2")
    old_trace = Trace(
        root_indicator_id=root1.id,
        depth=2,
        run_at=NOW - timedelta(days=1),
        truncated=False,
        summary={},
    )
    new_trace = Trace(root_indicator_id=root1.id, depth=2, run_at=NOW, truncated=False, summary={})
    other_trace = Trace(
        root_indicator_id=root2.id, depth=2, run_at=NOW, truncated=False, summary={}
    )
    db_session.add_all([old_trace, new_trace, other_trace])
    db_session.flush()
    # Only the OLD trace reached this terminal — it must be ignored now.
    db_session.add(
        TraceNodeRow(
            trace_id=old_trace.id,
            address="0xSTALE",
            hop=1,
            is_terminal=True,
            terminal_reason="mixer",
            labels=[],
        )
    )
    db_session.add(
        TraceNodeRow(
            trace_id=other_trace.id,
            address="0xSTALE",
            hop=1,
            is_terminal=True,
            terminal_reason="mixer",
            labels=[],
        )
    )
    db_session.commit()

    edges = list(SharesCashoutPathRelation(_config()).detect(db_session))
    assert edges == []  # root1's only sighting of 0xSTALE is via its superseded trace


# --- shares_cert ------------------------------------------------------


def test_cert_relation_links_domains_sharing_a_certificate(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    for d in (d1, d2):
        db_session.add(DomainProfile(indicator_id=d.id, enriched_at=NOW))
    db_session.add(
        DomainCert(
            indicator_id=d1.id,
            san="d1.example",
            issuer="LE",
            not_before=NOW,
            not_after=NOW,
            serial_number="S1",
        )
    )
    db_session.add(
        DomainCert(
            indicator_id=d2.id,
            san="d2.example",
            issuer="LE",
            not_before=NOW,
            not_after=NOW,
            serial_number="S1",
        )
    )
    db_session.commit()

    edges = list(SharesCertRelation(_config()).detect(db_session))

    assert len(edges) == 1
    edge = edges[0]
    assert edge.weight == 0.6
    assert edge.evidence["wildcard"] is False
    assert edge.evidence["cert_fingerprint"] == "LE||S1"
    assert set(edge.evidence["overlapping_sans"]) == {"d1.example", "d2.example"}


def test_cert_relation_discounts_wildcard_certs(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    for d in (d1, d2):
        db_session.add(DomainProfile(indicator_id=d.id, enriched_at=NOW))
    for i in range(25):
        db_session.add(
            DomainCert(
                indicator_id=d1.id,
                san=f"x{i}.wild.example",
                issuer="LE",
                not_before=NOW,
                not_after=NOW,
                serial_number="WILD",
            )
        )
        db_session.add(
            DomainCert(
                indicator_id=d2.id,
                san=f"x{i}.wild.example",
                issuer="LE",
                not_before=NOW,
                not_after=NOW,
                serial_number="WILD",
            )
        )
    db_session.commit()

    edges = list(SharesCertRelation(_config()).detect(db_session))

    assert len(edges) == 1
    assert edges[0].evidence["wildcard"] is True
    assert edges[0].weight == 0.1  # discounted, not the base 0.6
    assert edges[0].evidence["san_count"] == 25


def test_cert_relation_rejects_pair_outside_liveness_window(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    db_session.add(DomainProfile(indicator_id=d1.id, enriched_at=NOW))
    db_session.add(DomainProfile(indicator_id=d2.id, enriched_at=NOW + timedelta(days=200)))
    db_session.add(
        DomainCert(
            indicator_id=d1.id,
            san="d1.example",
            issuer="LE",
            not_before=NOW,
            not_after=NOW,
            serial_number="S1",
        )
    )
    db_session.add(
        DomainCert(
            indicator_id=d2.id,
            san="d2.example",
            issuer="LE",
            not_before=NOW,
            not_after=NOW,
            serial_number="S1",
        )
    )
    db_session.commit()

    edges = list(SharesCertRelation(_config()).detect(db_session))
    assert edges == []  # 200 days apart, default window is 90


# --- shares_registrar_and_ns --------------------------------------------


def test_registrar_ns_relation_requires_exact_match_on_both(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    d3 = _make_indicator(db_session, IndicatorType.DOMAIN, "d3.example")
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
    # Same registrar, different NS set: must not match.
    db_session.add(
        DomainProfile(
            indicator_id=d3.id, registrar="GoDaddy", ns_records=["ns3", "ns4"], enriched_at=NOW
        )
    )
    db_session.commit()

    edges = list(SharesRegistrarAndNsRelation(_config()).detect(db_session))

    assert len(edges) == 1
    assert {edges[0].src_indicator_id, edges[0].dst_indicator_id} == {d1.id, d2.id}
    assert edges[0].weight == 0.2


def test_registrar_ns_relation_skips_missing_data(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    db_session.add(
        DomainProfile(indicator_id=d1.id, registrar=None, ns_records=[], enriched_at=NOW)
    )
    db_session.add(
        DomainProfile(indicator_id=d2.id, registrar=None, ns_records=[], enriched_at=NOW)
    )
    db_session.commit()

    edges = list(SharesRegistrarAndNsRelation(_config()).detect(db_session))
    assert edges == []  # both missing registrar/NS — not a meaningful match


# --- shares_template ---------------------------------------------------


def test_template_relation_links_matching_body_hash(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    db_session.add(DomainProfile(indicator_id=d1.id, body_hash="HASH1", enriched_at=NOW))
    db_session.add(DomainProfile(indicator_id=d2.id, body_hash="HASH1", enriched_at=NOW))
    db_session.commit()

    edges = list(SharesTemplateRelation(_config()).detect(db_session))

    assert len(edges) == 1
    assert edges[0].weight == 0.5
    assert edges[0].evidence["matched_hashes"] == ["body_hash"]
    assert edges[0].evidence["body_hash"] == "HASH1"
    assert "src_fetched_at" in edges[0].evidence


def test_template_relation_notes_both_hashes_when_both_match(db_session: Session) -> None:
    d1 = _make_indicator(db_session, IndicatorType.DOMAIN, "d1.example")
    d2 = _make_indicator(db_session, IndicatorType.DOMAIN, "d2.example")
    db_session.add(
        DomainProfile(indicator_id=d1.id, body_hash="HASH1", favicon_hash="FAV1", enriched_at=NOW)
    )
    db_session.add(
        DomainProfile(indicator_id=d2.id, body_hash="HASH1", favicon_hash="FAV1", enriched_at=NOW)
    )
    db_session.commit()

    edges = list(SharesTemplateRelation(_config()).detect(db_session))

    assert len(edges) == 1  # one edge, not two, when multiple hashes match the same pair
    assert edges[0].evidence["matched_hashes"] == ["body_hash", "favicon_hash"]
