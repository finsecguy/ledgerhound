"""Builds the closed evidence universe an assessment draft may reason from.

`build_evidence_pack` reads everything Ledgerhound knows about a
campaign's members — indicators, edges and their evidence, chain-address
and domain projections, certs, labels, and the reliability grade of each
contributing source — and nothing else: no raw provider payloads, no
network access, no other campaign's data. The pack is a plain pydantic
model, serialized deterministically (`evidence_hash`) so a stored draft's
`evidence_hash` can always be checked against a freshly rebuilt pack to
detect drift, without ever needing to persist the pack itself.

Every item in the pack carries a stable `ref` string derived from the
underlying row's own natural identity (never a random id), so the same
database state always produces the same refs — a drafted assessment's
`supporting_evidence_refs` are checked against `EvidencePack.all_refs()`.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.db.models import (
    AddressLabel,
    AddressProfile,
    Assessment,
    Campaign,
    CampaignMember,
    DomainCert,
    DomainProfile,
    Edge,
    Indicator,
    IndicatorObservation,
    RawReport,
    Source,
    Trace,
)


class EvidenceMember(BaseModel):
    ref: str
    indicator_type: str
    value: str
    defanged_value: str
    first_seen: str
    last_seen: str


class EvidenceEdge(BaseModel):
    ref: str
    src_ref: str
    dst_ref: str
    relation: str
    weight: float
    evidence: dict[str, Any]


class EvidenceAddressProfile(BaseModel):
    ref: str
    member_ref: str
    chain: str
    tx_count: int
    total_received: str
    total_sent: str
    current_balance: str
    first_seen_onchain: str | None
    last_seen_onchain: str | None
    provider: str


class EvidenceTrace(BaseModel):
    ref: str
    member_ref: str
    depth: int
    truncated: bool
    summary: dict[str, Any]


class EvidenceDomainProfile(BaseModel):
    ref: str
    member_ref: str
    registrar: str | None
    ns_records: list[str]
    domain_created_at: str | None
    registrant_redacted: bool
    registered: bool | None
    http_status: int | None
    body_hash: str | None
    favicon_hash: str | None


class EvidenceCert(BaseModel):
    ref: str
    member_ref: str
    san: str
    issuer: str
    not_before: str
    not_after: str
    serial_number: str


class EvidenceLabel(BaseModel):
    ref: str
    member_ref: str
    label: str
    label_type: str
    source: str
    confidence: float


class SourceGrade(BaseModel):
    source_name: str
    reliability_grade: str


class EvidencePack(BaseModel):
    campaign_code: str
    members: list[EvidenceMember]
    edges: list[EvidenceEdge]
    address_profiles: list[EvidenceAddressProfile]
    traces: list[EvidenceTrace]
    domain_profiles: list[EvidenceDomainProfile]
    certs: list[EvidenceCert]
    labels: list[EvidenceLabel]
    source_grades: list[SourceGrade]
    #: The one number the model is never allowed to compute itself —
    #: `drafter.py` rejects a draft whose `financial.total_observed_inflow`
    #: doesn't match this exactly.
    total_observed_inflow: str

    def all_refs(self) -> set[str]:
        refs: set[str] = {m.ref for m in self.members}
        refs.update(e.ref for e in self.edges)
        refs.update(a.ref for a in self.address_profiles)
        refs.update(t.ref for t in self.traces)
        refs.update(d.ref for d in self.domain_profiles)
        refs.update(c.ref for c in self.certs)
        refs.update(lbl.ref for lbl in self.labels)
        return refs

    @property
    def evidence_hash(self) -> str:
        # sort_keys + compact separators: the same pack content always
        # serializes to the same bytes regardless of field-construction
        # order, so the same database state always hashes identically.
        canonical = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _member_ref(indicator_id: UUID) -> str:
    return f"member:{indicator_id}"


def build_evidence_pack(session: Session, campaign: Campaign) -> EvidencePack:
    member_ids = sorted(
        (
            row.indicator_id
            for row in session.scalars(
                select(CampaignMember).where(CampaignMember.campaign_id == campaign.id)
            )
        ),
        key=str,
    )
    indicators_by_id = {
        i.id: i for i in session.scalars(select(Indicator).where(Indicator.id.in_(member_ids)))
    }

    members = [
        EvidenceMember(
            ref=_member_ref(iid),
            indicator_type=indicators_by_id[iid].type.value,
            value=indicators_by_id[iid].value,
            defanged_value=indicators_by_id[iid].defanged_value,
            first_seen=indicators_by_id[iid].first_seen.isoformat(),
            last_seen=indicators_by_id[iid].last_seen.isoformat(),
        )
        for iid in member_ids
        if iid in indicators_by_id
    ]

    edge_rows = sorted(
        session.scalars(
            select(Edge).where(
                Edge.src_indicator_id.in_(member_ids), Edge.dst_indicator_id.in_(member_ids)
            )
        ),
        key=lambda e: (str(e.src_indicator_id), str(e.dst_indicator_id), e.relation.value),
    )
    edges = [
        EvidenceEdge(
            ref=f"edge:{e.src_indicator_id}:{e.dst_indicator_id}:{e.relation.value}",
            src_ref=_member_ref(e.src_indicator_id),
            dst_ref=_member_ref(e.dst_indicator_id),
            relation=e.relation.value,
            weight=e.weight,
            evidence=e.evidence,
        )
        for e in edge_rows
    ]

    address_profile_rows = sorted(
        session.scalars(select(AddressProfile).where(AddressProfile.indicator_id.in_(member_ids))),
        key=lambda p: str(p.indicator_id),
    )
    address_profiles = [
        EvidenceAddressProfile(
            ref=f"address_profile:{p.indicator_id}",
            member_ref=_member_ref(p.indicator_id),
            chain=p.chain,
            tx_count=p.tx_count,
            total_received=str(p.total_received),
            total_sent=str(p.total_sent),
            current_balance=str(p.current_balance),
            first_seen_onchain=p.first_seen_onchain.isoformat() if p.first_seen_onchain else None,
            last_seen_onchain=p.last_seen_onchain.isoformat() if p.last_seen_onchain else None,
            provider=p.provider,
        )
        for p in address_profile_rows
    ]
    # Wallet/cashout relations only ever link same-chain addresses (an
    # address string's format is chain-specific), and no relation links
    # an address indicator to a domain indicator — so a single campaign's
    # address members, if any, are always a single chain, and a plain
    # sum is meaningful. See the M3 README's "no cross-type
    # corroboration" limitation for why that invariant holds.
    total_observed_inflow = str(
        sum((p.total_received for p in address_profile_rows), Decimal(0))
    )

    trace_rows: list[Trace] = []
    for iid in member_ids:
        latest_trace = session.scalar(
            select(Trace)
            .where(Trace.root_indicator_id == iid)
            .order_by(Trace.run_at.desc())
            .limit(1)
        )
        if latest_trace is not None:
            trace_rows.append(latest_trace)
    trace_rows.sort(key=lambda t: str(t.root_indicator_id))
    traces = [
        EvidenceTrace(
            ref=f"trace:{t.id}",
            member_ref=_member_ref(t.root_indicator_id),
            depth=t.depth,
            truncated=t.truncated,
            summary=t.summary,
        )
        for t in trace_rows
    ]

    domain_profile_rows = sorted(
        session.scalars(select(DomainProfile).where(DomainProfile.indicator_id.in_(member_ids))),
        key=lambda p: str(p.indicator_id),
    )
    domain_profiles = [
        EvidenceDomainProfile(
            ref=f"domain_profile:{p.indicator_id}",
            member_ref=_member_ref(p.indicator_id),
            registrar=p.registrar,
            ns_records=sorted(p.ns_records),
            domain_created_at=p.domain_created_at.isoformat() if p.domain_created_at else None,
            registrant_redacted=p.registrant_redacted,
            registered=p.registered,
            http_status=p.http_status,
            body_hash=p.body_hash,
            favicon_hash=p.favicon_hash,
        )
        for p in domain_profile_rows
    ]

    cert_rows = sorted(
        session.scalars(select(DomainCert).where(DomainCert.indicator_id.in_(member_ids))),
        key=lambda c: (str(c.indicator_id), c.serial_number, c.san),
    )
    certs = [
        EvidenceCert(
            ref=f"cert:{c.indicator_id}:{c.serial_number}:{c.san}",
            member_ref=_member_ref(c.indicator_id),
            san=c.san,
            issuer=c.issuer,
            not_before=c.not_before.isoformat(),
            not_after=c.not_after.isoformat(),
            serial_number=c.serial_number,
        )
        for c in cert_rows
    ]

    label_rows = sorted(
        session.scalars(select(AddressLabel).where(AddressLabel.indicator_id.in_(member_ids))),
        key=lambda lbl: (str(lbl.indicator_id), lbl.label, lbl.source),
    )
    labels = [
        EvidenceLabel(
            ref=f"label:{lbl.indicator_id}:{lbl.label}:{lbl.source}",
            member_ref=_member_ref(lbl.indicator_id),
            label=lbl.label,
            label_type=lbl.label_type,
            source=lbl.source,
            confidence=lbl.confidence,
        )
        for lbl in label_rows
    ]

    source_rows = (
        session.execute(
            select(Source.name, Source.reliability_grade)
            .join(RawReport, RawReport.source_id == Source.id)
            .join(IndicatorObservation, IndicatorObservation.raw_report_id == RawReport.id)
            .where(IndicatorObservation.indicator_id.in_(member_ids))
            .distinct()
        ).all()
        if member_ids
        else []
    )
    source_grades = [
        SourceGrade(source_name=name, reliability_grade=grade)
        for name, grade in sorted(set(source_rows))
    ]

    return EvidencePack(
        campaign_code=campaign.code,
        members=members,
        edges=edges,
        address_profiles=address_profiles,
        traces=traces,
        domain_profiles=domain_profiles,
        certs=certs,
        labels=labels,
        source_grades=source_grades,
        total_observed_inflow=total_observed_inflow,
    )


def describe_refs(pack: EvidencePack) -> dict[str, str]:
    """Short human-readable text for every evidence-pack ref, so a draft's
    citations can be expanded inline instead of shown as opaque ref
    strings — used by both `lh assess show` and the dashboard's
    assessment endpoint, so the two never describe a ref differently."""
    descriptions: dict[str, str] = {}
    for member in pack.members:
        descriptions[member.ref] = f"{member.indicator_type}: {member.value}"
    for edge in pack.edges:
        descriptions[edge.ref] = (
            f"{edge.relation} between {edge.src_ref} and {edge.dst_ref} (weight {edge.weight})"
        )
    for profile in pack.address_profiles:
        descriptions[profile.ref] = (
            f"address profile ({profile.chain}): tx_count={profile.tx_count} "
            f"total_received={profile.total_received}"
        )
    for trace in pack.traces:
        descriptions[trace.ref] = f"trace (depth={trace.depth}, truncated={trace.truncated})"
    for domain in pack.domain_profiles:
        descriptions[domain.ref] = f"domain profile: registrar={domain.registrar or '-'}"
    for cert in pack.certs:
        descriptions[cert.ref] = f"cert issued by {cert.issuer} for {cert.san}"
    for label in pack.labels:
        descriptions[label.ref] = f"label {label.label} ({label.label_type}) from {label.source}"
    return descriptions


def refresh_staleness(session: Session, campaign_id: UUID, current_evidence_hash: str) -> None:
    """Mark the campaign's approved assessment (if any) stale when the
    evidence pack's hash no longer matches the one it was approved
    against. Called every time a fresh pack is built (drafting, editing)
    so staleness never depends on a separate maintenance job."""
    approved = session.scalar(
        select(Assessment).where(
            Assessment.campaign_id == campaign_id, Assessment.status == "approved"
        )
    )
    if approved is not None:
        approved.stale = approved.evidence_hash != current_evidence_hash
