"""shares_registrar_and_ns: two domain indicators registered through the
same registrar with the exact same nameserver set.

**This relation can never create a campaign on its own** — shared
registrar+NS is common infrastructure coincidence (cheap bulk-registered
domains routinely land on the same registrar and default nameservers) and
only corroborates an edge that already exists from a stronger relation.
That rule is enforced in `cluster.scoring`, not here: this detector just
emits the (deliberately low-weight) edges honestly.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.cluster.relations.base import EdgeCandidate, Relation, sorted_pairs
from ledgerhound.db.models import DomainProfile


class SharesRegistrarAndNsRelation(Relation):
    name = "shares_registrar_and_ns"
    base_weight = 0.2

    def detect(self, session: Session) -> Iterable[EdgeCandidate]:
        rows = session.execute(
            select(
                DomainProfile.indicator_id,
                DomainProfile.registrar,
                DomainProfile.ns_records,
                DomainProfile.domain_created_at,
            )
        ).all()

        groups: dict[tuple[str, tuple[str, ...]], list[UUID]] = defaultdict(list)
        created_at_by_indicator = {}
        for indicator_id, registrar, ns_records, created_at in rows:
            created_at_by_indicator[indicator_id] = created_at
            if not registrar or not ns_records:
                continue  # missing data isn't a meaningful match
            key = (registrar, tuple(sorted(ns_records)))
            groups[key].append(indicator_id)

        for registrar, ns_set in sorted(groups):
            indicator_ids = groups[(registrar, ns_set)]
            if len(set(indicator_ids)) < 2:
                continue

            for src_id, dst_id in sorted_pairs(indicator_ids):
                src_created = created_at_by_indicator.get(src_id)
                dst_created = created_at_by_indicator.get(dst_id)
                yield EdgeCandidate(
                    src_indicator_id=src_id,
                    dst_indicator_id=dst_id,
                    relation=self.name,
                    weight=self.config.weights.shares_registrar_and_ns,
                    evidence={
                        "registrar": registrar,
                        "ns_set": list(ns_set),
                        "src_created_at": src_created.isoformat() if src_created else None,
                        "dst_created_at": dst_created.isoformat() if dst_created else None,
                    },
                )
