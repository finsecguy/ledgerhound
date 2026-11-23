"""Downstream fund-flow tracing.

Breadth-first from a root address, following only *outbound* value
(where the scam's proceeds went), for a bounded number of hops. Depth 2
is the default because the stop conditions below are usually enough to
reach a real sink (an exchange, mixer, or bridge) within two hops of a
scam wallet, a scammer typically moves funds through one or two
intermediate "peeling" addresses before cashing out somewhere
recognizable. Depth is configurable per call up to a hard ceiling so a
pathological or mislabeled address can't trigger unbounded traversal.

Every cap this tracer hits. Breadth truncation, the depth ceiling, an
address it's already seen in this trace. Is recorded in the output.
`TraceResult.summary.truncated` exists specifically so a report generated
from this data can say "coverage may be incomplete" instead of silently
implying it traced everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from uuid import uuid4

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import AddressLabelHit, Chain, EnrichmentTarget
from ledgerhound.enrich.labels.known import KnownAddressIndex
from ledgerhound.enrich.labels.ofac import OFACList
from ledgerhound.enrich.registry import NoProviderAvailable, ProviderRegistry

DEFAULT_DEPTH = 2
DEFAULT_BREADTH = 25
HARD_DEPTH_CEILING = 5

#: Label types that stop a trace from expanding further, the funds have
#: reached a recognizable sink or a legally significant endpoint, not
#: just another indicator. `scam` is deliberately excluded: it marks
#: another known-bad address, not a place funds terminate.
_STOP_LABEL_TYPES = {"exchange", "mixer", "bridge", "sanctioned"}

_INDICATOR_TYPE_BY_CHAIN: dict[Chain, IndicatorType] = {
    "btc": IndicatorType.BTC_ADDRESS,
    "eth": IndicatorType.ETH_ADDRESS,
    "tron": IndicatorType.TRON_ADDRESS,
    "sol": IndicatorType.SOL_ADDRESS,
}


@dataclass(slots=True)
class TraceNode:
    address: str
    chain: Chain
    hop: int
    labels: list[AddressLabelHit]
    is_terminal: bool
    terminal_reason: str | None  # a _STOP_LABEL_TYPES value, "max_depth", or None


@dataclass(slots=True)
class TraceEdge:
    src: str
    dst: str
    hop: int
    value: Decimal
    tx_count: int


@dataclass(slots=True)
class TraceSummary:
    total_traced_value: Decimal
    terminal_counts: dict[str, int]
    truncated: bool
    #: True if any node could not be expanded because no provider in its
    #: facet's chain was available, a data-availability gap, distinct
    #: from a deliberate breadth/depth cap.
    incomplete_due_to_provider_failure: bool


@dataclass(slots=True)
class TraceResult:
    root_address: str
    chain: Chain
    depth: int
    breadth: int
    nodes: list[TraceNode] = field(default_factory=list)
    edges: list[TraceEdge] = field(default_factory=list)
    summary: TraceSummary = field(
        default_factory=lambda: TraceSummary(Decimal(0), {}, False, False)
    )


class Tracer:
    def __init__(
        self,
        registry: ProviderRegistry,
        *,
        ofac: OFACList | None = None,
        known: KnownAddressIndex | None = None,
    ) -> None:
        self._registry = registry
        self._ofac = ofac
        self._known = known

    def _labels_for(self, chain: Chain, address: str) -> list[AddressLabelHit]:
        labels: list[AddressLabelHit] = []
        if self._ofac is not None:
            ofac_hit = self._ofac.lookup(chain, address)
            if ofac_hit is not None:
                labels.append(
                    AddressLabelHit(
                        label=ofac_hit.entity_name or "OFAC SDN",
                        label_type="sanctioned",
                        source="OFAC SDN list",
                        confidence=1.0,
                    )
                )
        if self._known is not None:
            known_hit = self._known.lookup(chain, address)
            if known_hit is not None:
                labels.append(known_hit)
        return labels

    @staticmethod
    def _stop_reason(labels: list[AddressLabelHit]) -> str | None:
        for label in labels:
            if label.label_type in _STOP_LABEL_TYPES:
                return label.label_type
        return None

    async def trace(
        self,
        root_address: str,
        chain: Chain,
        *,
        depth: int = DEFAULT_DEPTH,
        breadth: int = DEFAULT_BREADTH,
    ) -> TraceResult:
        depth = min(depth, HARD_DEPTH_CEILING)
        indicator_type = _INDICATOR_TYPE_BY_CHAIN[chain]
        facet = indicator_type.value

        visited: set[str] = {root_address}
        root_labels = self._labels_for(chain, root_address)
        nodes: list[TraceNode] = [
            TraceNode(
                address=root_address,
                chain=chain,
                hop=0,
                labels=root_labels,
                is_terminal=self._stop_reason(root_labels) is not None,
                terminal_reason=self._stop_reason(root_labels),
            )
        ]
        edges: list[TraceEdge] = []
        terminal_counts: dict[str, int] = {}
        total_traced_value = Decimal(0)
        truncated = False
        incomplete = False

        frontier = [] if nodes[0].is_terminal else [root_address]

        for hop in range(1, depth + 1):
            next_frontier: list[str] = []
            for address in frontier:
                try:
                    result = await self._registry.enrich(
                        EnrichmentTarget(
                            indicator_id=uuid4(), type=indicator_type, value=address
                        ),
                        facet,
                    )
                except NoProviderAvailable:
                    incomplete = True
                    continue

                outbound = sorted(
                    (c for c in result.normalized.counterparties if c.direction == "out"),
                    key=lambda c: c.total_value,
                    reverse=True,
                )
                if len(outbound) > breadth:
                    truncated = True
                for counterparty in outbound[:breadth]:
                    total_traced_value += counterparty.total_value
                    edges.append(
                        TraceEdge(
                            src=address,
                            dst=counterparty.address,
                            hop=hop,
                            value=counterparty.total_value,
                            tx_count=counterparty.tx_count,
                        )
                    )
                    if counterparty.address in visited:
                        continue  # cycle: edge recorded, node not re-expanded

                    visited.add(counterparty.address)
                    labels = self._labels_for(chain, counterparty.address)
                    stop_reason = self._stop_reason(labels)
                    at_max_depth = hop == depth
                    is_terminal = stop_reason is not None or at_max_depth
                    reason = stop_reason or ("max_depth" if at_max_depth else None)
                    if reason:
                        terminal_counts[reason] = terminal_counts.get(reason, 0) + 1
                    nodes.append(
                        TraceNode(
                            address=counterparty.address,
                            chain=chain,
                            hop=hop,
                            labels=labels,
                            is_terminal=is_terminal,
                            terminal_reason=reason,
                        )
                    )
                    if not is_terminal:
                        next_frontier.append(counterparty.address)

            frontier = next_frontier
            if not frontier:
                break

        # A node terminated by hitting the depth ceiling (rather than by a
        # real stop-condition label) is exactly the case where the trace
        # would have kept going if allowed to. That's truncation.
        if terminal_counts.get("max_depth", 0) > 0:
            truncated = True

        return TraceResult(
            root_address=root_address,
            chain=chain,
            depth=depth,
            breadth=breadth,
            nodes=nodes,
            edges=edges,
            summary=TraceSummary(
                total_traced_value=total_traced_value,
                terminal_counts=terminal_counts,
                truncated=truncated,
                incomplete_due_to_provider_failure=incomplete,
            ),
        )

