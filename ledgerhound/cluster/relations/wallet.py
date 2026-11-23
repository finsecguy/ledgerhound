"""shares_receiving_wallet: two chain-address indicators that both sent
value out to the same third-party counterparty, a shared collection/
receiving wallet suggests the same actor controls both.

The shared wallet itself is excluded as a linking node when it's a known
exchange/mixer deposit address (checked via `LabelIndex`): two unrelated
scams both cashing out at the same Binance deposit cluster is not
evidence they're the same campaign.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.cluster.relations.base import EdgeCandidate, Relation, sorted_pairs
from ledgerhound.db.models import AddressCounterparty, AddressProfile, IndicatorObservation


def _raw_report_ids(session: Session, indicator_id: UUID) -> list[str]:
    ids = session.scalars(
        select(IndicatorObservation.raw_report_id)
        .where(IndicatorObservation.indicator_id == indicator_id)
        .distinct()
    ).all()
    return sorted(str(i) for i in ids)


class SharesReceivingWalletRelation(Relation):
    name = "shares_receiving_wallet"
    base_weight = 1.0

    def detect(self, session: Session) -> Iterable[EdgeCandidate]:
        rows = session.execute(
            select(
                AddressCounterparty.indicator_id,
                AddressCounterparty.counterparty_address,
                AddressProfile.chain,
            )
            .join(AddressProfile, AddressProfile.indicator_id == AddressCounterparty.indicator_id)
            .where(AddressCounterparty.direction == "out")
        ).all()

        groups: dict[str, set[tuple[UUID, str]]] = defaultdict(set)
        for indicator_id, wallet, chain in rows:
            groups[wallet].add((indicator_id, chain))

        for wallet in sorted(groups):
            members = groups[wallet]
            indicator_ids = {m[0] for m in members}
            if len(indicator_ids) < 2:
                continue

            # All members of a group share the same wallet string; the
            # chain is effectively the same across them in practice
            # (address formats don't collide across chains), so the
            # first member's chain is enough for the label check.
            chain = sorted(members, key=lambda m: str(m[0]))[0][1]
            if self.label_index is not None and self.label_index.is_excluded_linking_node(
                chain, wallet  # type: ignore[arg-type]
            ):
                continue

            for src_id, dst_id in sorted_pairs(indicator_ids):
                yield EdgeCandidate(
                    src_indicator_id=src_id,
                    dst_indicator_id=dst_id,
                    relation=self.name,
                    weight=self.config.weights.shares_receiving_wallet,
                    evidence={
                        "wallet": wallet,
                        "src_raw_report_ids": _raw_report_ids(session, src_id),
                        "dst_raw_report_ids": _raw_report_ids(session, dst_id),
                    },
                )

