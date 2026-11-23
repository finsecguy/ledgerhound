"""shares_cashout_path: two chain-address indicators whose downstream
fund-flow traces (`lh trace`) both reach the same *labeled* terminal
address, a shared cash-out destination.

Only labeled terminals count (exchange/mixer/bridge/sanctioned), a node
that's terminal purely because it hit the depth ceiling (`max_depth`)
isn't evidence of anything, it's just where the trace happened to stop.
Per the milestone's exclusion rule, the terminal address itself is never
a graph node. It appears only in this edge's evidence.

Reads whatever trace runs already exist in `traces`/`trace_nodes`
(populated by `lh trace`, persisted since milestone 3 fixed a gap left by
milestone 2). This relation does not, and, per the "clustering must be
deterministic, no network" constraint, must not. Trigger new traces.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.cluster.relations.base import EdgeCandidate, Relation, sorted_pairs
from ledgerhound.db.models import Trace, TraceNodeRow

#: A node terminal only because the trace hit its depth ceiling isn't a
#: cash-out destination. It's just where we stopped looking.
_CASHOUT_TERMINAL_REASONS = {"exchange", "mixer", "bridge", "sanctioned"}


def _latest_trace_per_root(session: Session) -> dict[UUID, UUID]:
    """root_indicator_id -> its most recent trace_id (an indicator may
    have been traced more than once over time)."""
    latest: dict[UUID, tuple[UUID, datetime]] = {}
    for trace_id, root_id, run_at in session.execute(
        select(Trace.id, Trace.root_indicator_id, Trace.run_at)
    ):
        current = latest.get(root_id)
        if current is None or run_at > current[1]:
            latest[root_id] = (trace_id, run_at)
    return {root_id: trace_id for root_id, (trace_id, _run_at) in latest.items()}


class SharesCashoutPathRelation(Relation):
    name = "shares_cashout_path"
    base_weight = 0.8

    def detect(self, session: Session) -> Iterable[EdgeCandidate]:
        trace_by_root = _latest_trace_per_root(session)
        if not trace_by_root:
            return

        trace_to_root = {trace_id: root_id for root_id, trace_id in trace_by_root.items()}

        # terminal_address -> list of (root_indicator_id, hop, terminal_reason, labels)
        by_terminal: dict[str, list[tuple[UUID, int, str, list[dict[str, object]]]]] = defaultdict(
            list
        )
        rows = session.execute(
            select(
                TraceNodeRow.trace_id,
                TraceNodeRow.address,
                TraceNodeRow.hop,
                TraceNodeRow.terminal_reason,
                TraceNodeRow.labels,
            ).where(
                TraceNodeRow.is_terminal.is_(True),
                TraceNodeRow.trace_id.in_(trace_to_root.keys()),
            )
        ).all()
        for trace_id, address, hop, terminal_reason, labels in rows:
            if terminal_reason not in _CASHOUT_TERMINAL_REASONS:
                continue
            # Every trace_id here came from trace_to_root's keys (the
            # query filtered on that), so this is always the latest
            # trace for its root by construction.
            root_id = trace_to_root[trace_id]
            by_terminal[address].append((root_id, hop, terminal_reason, labels))

        for terminal_address in sorted(by_terminal):
            hits = by_terminal[terminal_address]
            roots = {h[0] for h in hits}
            if len(roots) < 2:
                continue

            hop_by_root: dict[UUID, int] = {}
            reason_by_root: dict[UUID, str] = {}
            labels_by_root: dict[UUID, list[dict[str, object]]] = {}
            for root_id, hop, reason, labels in hits:
                # If a root reached this terminal via more than one path
                # (shouldn't normally happen, cycles aside), keep the
                # shortest hop deterministically.
                if root_id not in hop_by_root or hop < hop_by_root[root_id]:
                    hop_by_root[root_id] = hop
                    reason_by_root[root_id] = reason
                    labels_by_root[root_id] = labels

            for src_id, dst_id in sorted_pairs(roots):
                yield EdgeCandidate(
                    src_indicator_id=src_id,
                    dst_indicator_id=dst_id,
                    relation=self.name,
                    weight=self.config.weights.shares_cashout_path,
                    evidence={
                        "terminal_address": terminal_address,
                        "terminal_label_type": reason_by_root[src_id],
                        "terminal_labels": labels_by_root[src_id],
                        "hop_from_src": hop_by_root[src_id],
                        "hop_from_dst": hop_by_root[dst_id],
                    },
                )

