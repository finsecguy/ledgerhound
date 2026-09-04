"""shares_cert: two domain indicators covered by the same TLS
certificate (same issuer + serial number — crt.sh doesn't give us the
literal SHA-256 fingerprint via the fields milestone 2 captured, so
`{issuer}||{serial_number}` is the practical, equally-unique substitute:
it's exactly what you'd look up on crt.sh by hand to verify this).

A cert covering many SANs (shared hosting, a CDN, Let's Encrypt on a
platform like Vercel/Netlify) is discounted rather than treated as a
meaningful link — two phishing sites both hosted on Vercel share a cert
with thousands of unrelated SANs, and that's infrastructure, not
evidence of a relationship.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.cluster.relations.base import EdgeCandidate, Relation, sorted_pairs
from ledgerhound.db.models import DomainCert, DomainProfile


@dataclass(slots=True)
class _CertGroup:
    indicator_ids: set[UUID] = field(default_factory=set)
    sans: set[str] = field(default_factory=set)
    not_before: datetime | None = None
    not_after: datetime | None = None


class SharesCertRelation(Relation):
    name = "shares_cert"
    base_weight = 0.6

    def detect(self, session: Session) -> Iterable[EdgeCandidate]:
        cert_rows = session.execute(
            select(
                DomainCert.indicator_id,
                DomainCert.issuer,
                DomainCert.serial_number,
                DomainCert.san,
                DomainCert.not_before,
                DomainCert.not_after,
            )
        ).all()

        groups: dict[tuple[str, str], _CertGroup] = {}
        for indicator_id, issuer, serial, san, not_before, not_after in cert_rows:
            group = groups.setdefault((issuer, serial), _CertGroup())
            group.indicator_ids.add(indicator_id)
            group.sans.add(san)
            group.not_before = group.not_before or not_before
            group.not_after = group.not_after or not_after

        enriched_at_by_indicator: dict[UUID, datetime] = dict(
            session.execute(
                select(DomainProfile.indicator_id, DomainProfile.enriched_at)
            ).tuples().all()
        )
        liveness_window = timedelta(days=self.config.cert.liveness_window_days)
        san_threshold = self.config.cert.wildcard_san_threshold
        wildcard_weight = self.config.cert.wildcard_weight
        base_weight = self.config.weights.shares_cert

        for issuer, serial in sorted(groups):
            group = groups[(issuer, serial)]
            if len(group.indicator_ids) < 2:
                continue

            sans = sorted(group.sans)
            is_wildcard = len(sans) > san_threshold
            weight = wildcard_weight if is_wildcard else base_weight

            for src_id, dst_id in sorted_pairs(group.indicator_ids):
                src_seen = enriched_at_by_indicator.get(src_id)
                dst_seen = enriched_at_by_indicator.get(dst_id)
                if src_seen is None or dst_seen is None:
                    continue
                if abs(src_seen - dst_seen) > liveness_window:
                    continue

                yield EdgeCandidate(
                    src_indicator_id=src_id,
                    dst_indicator_id=dst_id,
                    relation=self.name,
                    weight=weight,
                    evidence={
                        "cert_fingerprint": f"{issuer}||{serial}",
                        "issuer": issuer,
                        "serial_number": serial,
                        "overlapping_sans": sans,
                        "not_before": group.not_before.isoformat() if group.not_before else None,
                        "not_after": group.not_after.isoformat() if group.not_after else None,
                        "wildcard": is_wildcard,
                        "san_count": len(sans),
                    },
                )
