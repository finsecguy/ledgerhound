"""shares_template: two domain indicators serving byte-identical page
content (body hash) and/or a byte-identical favicon, the same phishing
kit deployed on different domains.

Same liveness-window requirement as `shares_cert`: two domains only count
as sharing a template if their HTTP fingerprints were captured within
`liveness_window_days` of each other.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.cluster.relations.base import EdgeCandidate, Relation, sorted_pairs
from ledgerhound.db.models import DomainProfile


def _pairs_by_hash(rows: list[tuple[UUID, str | None]]) -> dict[str, set[UUID]]:
    groups: dict[str, set[UUID]] = defaultdict(set)
    for indicator_id, value in rows:
        if value:
            groups[value].add(indicator_id)
    return {value: ids for value, ids in groups.items() if len(ids) >= 2}


class SharesTemplateRelation(Relation):
    name = "shares_template"
    base_weight = 0.5

    def detect(self, session: Session) -> Iterable[EdgeCandidate]:
        rows = session.execute(
            select(
                DomainProfile.indicator_id,
                DomainProfile.body_hash,
                DomainProfile.favicon_hash,
                DomainProfile.enriched_at,
            )
        ).all()

        enriched_at_by_indicator: dict[UUID, datetime] = {
            indicator_id: enriched_at for indicator_id, _b, _f, enriched_at in rows
        }
        body_groups = _pairs_by_hash([(r[0], r[1]) for r in rows])
        favicon_groups = _pairs_by_hash([(r[0], r[2]) for r in rows])

        # pair -> {"body": hash | None, "favicon": hash | None}
        matched_pairs: dict[tuple[UUID, UUID], dict[str, str]] = defaultdict(dict)
        for body_hash in sorted(body_groups):
            for pair in sorted_pairs(body_groups[body_hash]):
                matched_pairs[pair]["body_hash"] = body_hash
        for favicon_hash in sorted(favicon_groups):
            for pair in sorted_pairs(favicon_groups[favicon_hash]):
                matched_pairs[pair]["favicon_hash"] = favicon_hash

        liveness_window = timedelta(days=self.config.template.liveness_window_days)

        for src_id, dst_id in sorted(matched_pairs, key=lambda p: (str(p[0]), str(p[1]))):
            src_seen = enriched_at_by_indicator.get(src_id)
            dst_seen = enriched_at_by_indicator.get(dst_id)
            if src_seen is None or dst_seen is None:
                continue
            if abs(src_seen - dst_seen) > liveness_window:
                continue

            matched = matched_pairs[(src_id, dst_id)]
            yield EdgeCandidate(
                src_indicator_id=src_id,
                dst_indicator_id=dst_id,
                relation=self.name,
                weight=self.config.weights.shares_template,
                evidence={
                    "matched_hashes": sorted(matched),
                    **matched,
                    "src_fetched_at": src_seen.isoformat(),
                    "dst_fetched_at": dst_seen.isoformat(),
                },
            )

