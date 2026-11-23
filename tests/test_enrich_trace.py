"""Fund-flow tracer tests: depth respected, breadth cap truncates and sets
the flag, cycles terminate without re-expansion, and stop-condition labels
halt expansion at the labeled node. All against a fake in-memory Provider
graph, no network."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import (
    AddressLabelHit,
    ChainAddressProfile,
    Counterparty,
    EnrichmentTarget,
    Provider,
    ProviderResult,
    RateLimit,
)
from ledgerhound.enrich.chain.trace import Tracer
from ledgerhound.enrich.registry import ProviderRegistry


class _FakeKnown:
    def __init__(self, labeled: dict[str, AddressLabelHit]) -> None:
        self._labeled = labeled

    def lookup(self, chain: str, address: str) -> AddressLabelHit | None:
        return self._labeled.get(address)


def _make_provider(graph: dict[str, list[tuple[str, int]]]) -> Provider:
    class FakeProvider(Provider):
        name = "fake"
        supports = {IndicatorType.BTC_ADDRESS}
        rate_limit = RateLimit(max_requests=1000, per_seconds=1)
        ttl = timedelta(hours=1)

        async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
            counterparties = [
                Counterparty(address=addr, direction="out", tx_count=1, total_value=Decimal(v))
                for addr, v in graph.get(target.value, [])
            ]
            return ProviderResult(
                provider=self.name,
                raw={},
                normalized=ChainAddressProfile(
                    chain="btc", address=target.value, decimals=8, counterparties=counterparties
                ),
                fetched_at=datetime.now(UTC),
            )

    return FakeProvider(client=None)  # type: ignore[arg-type]


async def test_trace_respects_depth_and_records_max_depth_terminals() -> None:
    graph = {
        "root": [("hop1", 100)],
        "hop1": [("hop2", 50)],
        "hop2": [("hop3", 25)],
    }
    registry = ProviderRegistry({"btc_address": [_make_provider(graph)]})
    tracer = Tracer(registry)

    result = await tracer.trace("root", "btc", depth=2, breadth=25)

    addresses = {n.address for n in result.nodes}
    assert addresses == {"root", "hop1", "hop2"}  # hop3 never reached: depth=2
    hop2_node = next(n for n in result.nodes if n.address == "hop2")
    assert hop2_node.is_terminal is True
    assert hop2_node.terminal_reason == "max_depth"
    assert result.summary.truncated is True  # depth cap cut off real further expansion


async def test_trace_breadth_cap_keeps_highest_value_edges_and_sets_truncated() -> None:
    graph = {"root": [(f"cp{i}", 100 - i) for i in range(5)]}
    registry = ProviderRegistry({"btc_address": [_make_provider(graph)]})
    tracer = Tracer(registry)

    result = await tracer.trace("root", "btc", depth=1, breadth=2)

    kept = {n.address for n in result.nodes if n.address != "root"}
    assert kept == {"cp0", "cp1"}  # top two by value (100, 99); cp2..cp4 dropped
    assert result.summary.truncated is True


async def test_trace_cycle_is_recorded_but_not_re_expanded() -> None:
    graph = {
        "root": [("mid", 100)],
        "mid": [("root", 50)],  # cycles back
    }
    registry = ProviderRegistry({"btc_address": [_make_provider(graph)]})
    tracer = Tracer(registry)

    result = await tracer.trace("root", "btc", depth=3, breadth=25)

    # root appears exactly once as a node despite the cycle edge back to it.
    assert sum(1 for n in result.nodes if n.address == "root") == 1
    # The cycle-forming edge is still recorded as evidence of the fund flow.
    assert any(e.src == "mid" and e.dst == "root" for e in result.edges)


async def test_trace_stops_at_labeled_terminal_node_and_does_not_expand_past_it() -> None:
    graph = {
        "root": [("exchange_addr", 100)],
        "exchange_addr": [("should_not_appear", 999)],
    }
    known = _FakeKnown(
        {
            "exchange_addr": AddressLabelHit(
                label="Big Exchange", label_type="exchange", source="test", confidence=1.0
            )
        }
    )
    registry = ProviderRegistry({"btc_address": [_make_provider(graph)]})
    tracer = Tracer(registry, known=known)  # type: ignore[arg-type]

    result = await tracer.trace("root", "btc", depth=5, breadth=25)

    addresses = {n.address for n in result.nodes}
    assert "exchange_addr" in addresses
    assert "should_not_appear" not in addresses  # never expanded past the label
    exchange_node = next(n for n in result.nodes if n.address == "exchange_addr")
    assert exchange_node.is_terminal is True
    assert exchange_node.terminal_reason == "exchange"
    # A real stop-condition, not a cap: this alone shouldn't mark truncated.
    assert result.summary.truncated is False


async def test_trace_scam_label_does_not_halt_expansion() -> None:
    """`scam` marks another known-bad address, not a fund sink. Tracing
    must continue past it, unlike exchange/mixer/bridge/sanctioned."""
    graph = {
        "root": [("scam_addr", 100)],
        "scam_addr": [("downstream", 50)],
    }
    known = _FakeKnown(
        {
            "scam_addr": AddressLabelHit(
                label="Known Scam", label_type="scam", source="test", confidence=1.0
            )
        }
    )
    registry = ProviderRegistry({"btc_address": [_make_provider(graph)]})
    tracer = Tracer(registry, known=known)  # type: ignore[arg-type]

    result = await tracer.trace("root", "btc", depth=2, breadth=25)

    addresses = {n.address for n in result.nodes}
    assert "downstream" in addresses

