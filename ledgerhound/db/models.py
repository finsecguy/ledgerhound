"""ORM models for the Ledgerhound schema.

Six tables, per the milestone 1 spec:

- ``sources``      — configured feeds Ledgerhound collects from.
- ``raw_reports``  — deduplicated raw payloads fetched from a source.
- ``indicators``   — canonicalized IOCs (addresses, domains, URLs, handles).
- ``indicator_observations`` — join table: which raw report an indicator
  was seen in, and when.
- ``enrichment``   — provider lookups against an indicator. Unused until
  milestone 2; the table exists now so the schema doesn't need a breaking
  migration later.
- ``edges``        — inferred relationships between indicators, the basis
  for campaign clustering. Unused until milestone 3, same rationale.

All tables share a UUID primary key and timezone-aware ``created_at`` /
``updated_at`` timestamps via ``TimestampMixin``.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ledgerhound.db.types import GUID, JSONB, PreciseNumeric, UTCDateTime


class Base(DeclarativeBase):
    """Declarative base for all Ledgerhound models."""


class TimestampMixin:
    """Adds a UUID primary key and UTC created_at/updated_at columns."""

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SourceType(enum.StrEnum):
    SCAM_REPORT = "scam_report"
    PHISHING_FEED = "phishing_feed"
    CHAT_CHANNEL = "chat_channel"


class IndicatorType(enum.StrEnum):
    BTC_ADDRESS = "btc_address"
    ETH_ADDRESS = "eth_address"
    TRON_ADDRESS = "tron_address"
    SOL_ADDRESS = "sol_address"
    DOMAIN = "domain"
    URL = "url"
    TELEGRAM_HANDLE = "telegram_handle"


class EdgeRelation(enum.StrEnum):
    SHARES_RECEIVING_WALLET = "shares_receiving_wallet"
    SHARES_CASHOUT_PATH = "shares_cashout_path"
    SHARES_CERT = "shares_cert"
    SHARES_REGISTRAR_AND_NS = "shares_registrar_and_ns"
    SHARES_TEMPLATE = "shares_template"


_ADMIRALTY_GRADES = ("A", "B", "C", "D", "E", "F")
_ADMIRALTY_GRADES_SQL = ", ".join(f"'{grade}'" for grade in _ADMIRALTY_GRADES)


class Source(TimestampMixin, Base):
    """A configured feed Ledgerhound collects raw reports from."""

    __tablename__ = "sources"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    type: Mapped[SourceType] = mapped_column(
        Enum(SourceType, name="source_type", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    cadence_minutes: Mapped[int] = mapped_column(nullable=False)
    reliability_grade: Mapped[str] = mapped_column(String(1), nullable=False)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)

    raw_reports: Mapped[list[RawReport]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            f"reliability_grade IN ({_ADMIRALTY_GRADES_SQL})",
            name="ck_sources_reliability_grade",
        ),
    )


class RawReport(TimestampMixin, Base):
    """A deduplicated raw payload fetched from a source.

    Dedupe key is (source_id, content_hash): a collector fetches the same
    upstream record more than once (re-fetching an unchanged feed), and
    that must not create a second row.
    """

    __tablename__ = "raw_reports"

    source_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    source: Mapped[Source] = relationship(back_populates="raw_reports")
    observations: Mapped[list[IndicatorObservation]] = relationship(
        back_populates="raw_report", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("source_id", "content_hash", name="uq_raw_reports_source_content_hash"),
        Index("ix_raw_reports_source_id", "source_id"),
        Index("ix_raw_reports_content_hash", "content_hash"),
    )


class Indicator(TimestampMixin, Base):
    """A canonicalized indicator of compromise."""

    __tablename__ = "indicators"

    type: Mapped[IndicatorType] = mapped_column(
        Enum(
            IndicatorType, name="indicator_type", values_callable=lambda e: [m.value for m in e]
        ),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    defanged_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    observations: Mapped[list[IndicatorObservation]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan"
    )
    enrichments: Mapped[list[Enrichment]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_indicators_type_value"),
        Index("ix_indicators_value", "value"),
        Index("ix_indicators_type", "type"),
    )


class IndicatorObservation(TimestampMixin, Base):
    """One sighting of an indicator within a specific raw report."""

    __tablename__ = "indicator_observations"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    raw_report_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("raw_reports.id", ondelete="CASCADE"), nullable=False
    )
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    indicator: Mapped[Indicator] = relationship(back_populates="observations")
    raw_report: Mapped[RawReport] = relationship(back_populates="observations")

    __table_args__ = (
        UniqueConstraint(
            "indicator_id", "raw_report_id", name="uq_indicator_observations_indicator_report"
        ),
        Index("ix_indicator_observations_indicator_id", "indicator_id"),
        Index("ix_indicator_observations_raw_report_id", "raw_report_id"),
    )


class Enrichment(TimestampMixin, Base):
    """A provider lookup result for an indicator. Unused until milestone 2."""

    __tablename__ = "enrichment"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    indicator: Mapped[Indicator] = relationship(back_populates="enrichments")

    __table_args__ = (Index("ix_enrichment_indicator_id", "indicator_id"),)


class Edge(TimestampMixin, Base):
    """An inferred relationship between two indicators. Unused until milestone 3."""

    __tablename__ = "edges"

    src_indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    dst_indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    relation: Mapped[EdgeRelation] = mapped_column(
        Enum(EdgeRelation, name="edge_relation", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    weight: Mapped[float] = mapped_column(Float(), nullable=False, default=1.0)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False, default=dict)

    src_indicator: Mapped[Indicator] = relationship(foreign_keys=[src_indicator_id])
    dst_indicator: Mapped[Indicator] = relationship(foreign_keys=[dst_indicator_id])

    __table_args__ = (
        UniqueConstraint(
            "src_indicator_id", "dst_indicator_id", "relation", name="uq_edges_src_dst_relation"
        ),
        Index("ix_edges_src_indicator_id", "src_indicator_id"),
        Index("ix_edges_dst_indicator_id", "dst_indicator_id"),
        CheckConstraint("src_indicator_id != dst_indicator_id", name="ck_edges_no_self_loop"),
    )


# --- Milestone 2: enrichment projection tables -------------------------
#
# Raw provider payloads stay in `enrichment` (JSONB, provider-tagged).
# These tables are the normalized projection milestone 3's clustering
# queries directly, instead of parsing raw payloads on every read.
# Monetary values are `Numeric` (Python `Decimal`), never float, on both
# Postgres and SQLite — matching the normalized pydantic models in
# `ledgerhound.enrich.base`.

_CHAIN_VALUES_SQL = "'btc', 'eth', 'tron', 'sol'"
_LABEL_TYPES_SQL = "'exchange', 'mixer', 'bridge', 'sanctioned', 'scam'"


class AddressProfile(TimestampMixin, Base):
    """Latest normalized chain-address snapshot; one row per indicator,
    replaced wholesale on each re-enrichment."""

    __tablename__ = "address_profiles"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    chain: Mapped[str] = mapped_column(String(10), nullable=False)
    first_seen_onchain: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_seen_onchain: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    tx_count: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    total_received: Mapped[Decimal] = mapped_column(
        PreciseNumeric(), nullable=False, default=Decimal(0)
    )
    total_sent: Mapped[Decimal] = mapped_column(
        PreciseNumeric(), nullable=False, default=Decimal(0)
    )
    current_balance: Mapped[Decimal] = mapped_column(
        PreciseNumeric(), nullable=False, default=Decimal(0)
    )
    decimals: Mapped[int] = mapped_column(Integer(), nullable=False)
    provider: Mapped[str] = mapped_column(String(255), nullable=False)
    enriched_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    __table_args__ = (
        CheckConstraint(f"chain IN ({_CHAIN_VALUES_SQL})", name="ck_address_profiles_chain"),
    )


class AddressCounterparty(TimestampMixin, Base):
    """One aggregated counterparty relationship for a tracked address."""

    __tablename__ = "address_counterparties"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    counterparty_address: Mapped[str] = mapped_column(String(255), nullable=False)
    direction: Mapped[str] = mapped_column(String(3), nullable=False)
    tx_count: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    total_value: Mapped[Decimal] = mapped_column(
        PreciseNumeric(), nullable=False, default=Decimal(0)
    )

    __table_args__ = (
        UniqueConstraint(
            "indicator_id",
            "counterparty_address",
            "direction",
            name="uq_address_counterparties_indicator_addr_dir",
        ),
        Index("ix_address_counterparties_indicator_id", "indicator_id"),
        Index("ix_address_counterparties_counterparty_address", "counterparty_address"),
        CheckConstraint("direction IN ('in', 'out')", name="ck_address_counterparties_direction"),
    )


class AddressLabel(TimestampMixin, Base):
    """A label (exchange/mixer/bridge/sanctioned/scam) attached to a
    tracked chain address, with source and confidence for provenance."""

    __tablename__ = "address_labels"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    label_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[str] = mapped_column(String(500), nullable=False)
    confidence: Mapped[float] = mapped_column(Float(), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "indicator_id", "label", "source", name="uq_address_labels_indicator_label_source"
        ),
        Index("ix_address_labels_indicator_id", "indicator_id"),
        CheckConstraint(
            f"label_type IN ({_LABEL_TYPES_SQL})", name="ck_address_labels_label_type"
        ),
    )


class DomainProfile(TimestampMixin, Base):
    """Latest normalized domain snapshot, merging the DNS/RDAP/HTTP
    facets (certs get their own table since a domain has many)."""

    __tablename__ = "domain_profiles"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain_created_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    domain_updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    domain_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    registrant_country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    registrant_redacted: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    #: True/False once a registration-data provider (RDAP or WHOIS) has
    #: actually answered; null means neither has run yet for this domain.
    registered: Mapped[bool | None] = mapped_column(Boolean(), nullable=True)
    #: Domain status codes (RDAP `status` / WHOIS "Domain Status"), e.g.
    #: "clientTransferProhibited".
    status: Mapped[list[str]] = mapped_column(JSONB(), nullable=False, default=list)
    #: Which provider actually served the registration-data facet — RDAP
    #: (via IANA bootstrap or rdap.org) or the WHOIS fallback. Distinct
    #: from `enrichment.provider`, which is per raw-payload row; this is
    #: specifically for the registration-data half of this merged
    #: projection, since DNS/certs/HTTP each have their own provider too
    #: (recorded in `enrichment`, not broken out into their own column
    #: here — only registration data's provenance was asked for).
    registration_provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ns_records: Mapped[list[str]] = mapped_column(JSONB(), nullable=False, default=list)
    asn: Mapped[str | None] = mapped_column(String(32), nullable=True)
    nxdomain: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    http_status: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    http_server_header: Mapped[str | None] = mapped_column(String(255), nullable=True)
    body_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    favicon_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enriched_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    __table_args__ = (
        Index("ix_domain_profiles_asn", "asn"),
        Index("ix_domain_profiles_registrar", "registrar"),
        Index("ix_domain_profiles_body_hash", "body_hash"),
        Index("ix_domain_profiles_favicon_hash", "favicon_hash"),
    )


class DomainCert(TimestampMixin, Base):
    """One certificate-transparency-observed SAN for a tracked domain."""

    __tablename__ = "domain_certs"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    san: Mapped[str] = mapped_column(String(500), nullable=False)
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    not_before: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    not_after: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "indicator_id", "serial_number", "san", name="uq_domain_certs_indicator_serial_san"
        ),
        Index("ix_domain_certs_indicator_id", "indicator_id"),
        Index("ix_domain_certs_san", "san"),
    )


class Trace(TimestampMixin, Base):
    """One `lh trace` run against a root chain address."""

    __tablename__ = "traces"

    root_indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    depth: Mapped[int] = mapped_column(Integer(), nullable=False)
    run_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False, default=dict)

    __table_args__ = (Index("ix_traces_root_indicator_id", "root_indicator_id"),)


class TraceEdgeRow(TimestampMixin, Base):
    """One edge discovered during a trace run.

    Named `...Row` (rather than `TraceEdge`) to avoid colliding with
    `ledgerhound.enrich.chain.trace.TraceEdge`, the in-memory dataclass a
    trace run produces before it's persisted here.
    """

    __tablename__ = "trace_edges"

    trace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("traces.id", ondelete="CASCADE"), nullable=False
    )
    src_address: Mapped[str] = mapped_column(String(255), nullable=False)
    dst_address: Mapped[str] = mapped_column(String(255), nullable=False)
    hop: Mapped[int] = mapped_column(Integer(), nullable=False)
    value: Mapped[Decimal] = mapped_column(PreciseNumeric(), nullable=False)
    tx_count: Mapped[int] = mapped_column(Integer(), nullable=False)

    __table_args__ = (
        Index("ix_trace_edges_trace_id", "trace_id"),
        Index("ix_trace_edges_src_address", "src_address"),
        Index("ix_trace_edges_dst_address", "dst_address"),
    )


class TraceNodeRow(TimestampMixin, Base):
    """One node (address) visited during a trace run, with its hop
    distance and terminal classification.

    Added in milestone 3: milestone 2's `lh trace` computed this data in
    memory (to print it) but never persisted it, leaving `traces`/
    `trace_edges` populated with edges but no way to know which addresses
    were terminal or why. `shares_cashout_path` needs exactly that — two
    different indicators' traces reaching the same *labeled* terminal
    node — so this table fills the gap.
    """

    __tablename__ = "trace_nodes"

    trace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("traces.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    hop: Mapped[int] = mapped_column(Integer(), nullable=False)
    is_terminal: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    #: One of the Tracer's `_STOP_LABEL_TYPES` ("exchange"/"mixer"/
    #: "bridge"/"sanctioned"), "max_depth", or null (non-terminal node).
    terminal_reason: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: [{"label": ..., "label_type": ..., "source": ..., "confidence": ...}, ...]
    labels: Mapped[list[dict[str, Any]]] = mapped_column(JSONB(), nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint("trace_id", "address", name="uq_trace_nodes_trace_address"),
        Index("ix_trace_nodes_trace_id", "trace_id"),
        Index("ix_trace_nodes_address", "address"),
    )


# --- Milestone 3: clustering -------------------------------------------
#
# `edges` (milestone 1's schema) is populated here for the first time —
# each `cluster.relations.*` detector writes indicator-to-indicator edges
# with evidence. Connected components of that graph above a score
# threshold become campaigns.

_CAMPAIGN_STATUS_SQL = "'active', 'dormant'"


class Campaign(TimestampMixin, Base):
    """A cluster of indicators believed to be the same scam campaign.

    `code` is assigned once (`LH-YYYY-NNN`) and never changes; identity
    is stable across re-runs via Jaccard overlap matching in
    `cluster.campaigns`, not by recomputing from scratch each time.
    """

    __tablename__ = "campaigns"

    code: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    #: Survives re-runs even though `code` and computed fields don't
    #: depend on it — an analyst-assigned label.
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="active")
    score: Mapped[float] = mapped_column(Float(), nullable=False)
    #: Distinct relation types present among this campaign's edges — the
    #: literal evidence that it isn't a registrar/NS-only false positive.
    relation_types: Mapped[list[str]] = mapped_column(JSONB(), nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    __table_args__ = (
        CheckConstraint(f"status IN ({_CAMPAIGN_STATUS_SQL})", name="ck_campaigns_status"),
    )


class CampaignMember(TimestampMixin, Base):
    """One indicator's membership in one campaign."""

    __tablename__ = "campaign_members"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    joined_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "campaign_id", "indicator_id", name="uq_campaign_members_campaign_indicator"
        ),
        Index("ix_campaign_members_campaign_id", "campaign_id"),
        Index("ix_campaign_members_indicator_id", "indicator_id"),
    )


class CampaignEvent(TimestampMixin, Base):
    """A merge or split affecting a campaign's membership across runs,
    with the exact before/after member sets so a report can cite history
    precisely rather than just asserting "this campaign changed."""

    __tablename__ = "campaign_events"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(10), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    #: Codes of the other campaign(s) involved — absorbed into this one
    #: (merge) or split out of it (split).
    related_campaign_codes: Mapped[list[str]] = mapped_column(JSONB(), nullable=False, default=list)
    #: Indicator ids (as strings) — this campaign's membership immediately
    #: before and after the event.
    members_before: Mapped[list[str]] = mapped_column(JSONB(), nullable=False)
    members_after: Mapped[list[str]] = mapped_column(JSONB(), nullable=False)

    __table_args__ = (
        CheckConstraint("event_type IN ('merge', 'split')", name="ck_campaign_events_event_type"),
        Index("ix_campaign_events_campaign_id", "campaign_id"),
    )


# --- Milestone 4: assessment -------------------------------------------
#
# The LLM drafts; the analyst decides. Every draft the model produces is
# a new, immutable version row here — editing or re-drafting never
# overwrites a prior version, so `lh assess diff` and the audit trail
# (who approved/rejected what, and when) always have something to show.

_ASSESSMENT_STATUS_SQL = "'draft', 'in_review', 'approved', 'rejected'"


class Assessment(TimestampMixin, Base):
    """One versioned analytic assessment draft for a campaign.

    `evidence_hash` is the sha256 of the deterministic `EvidencePack` the
    draft was produced (or re-validated, for a human edit) against —
    every draft can be traced back to exactly what evidence produced it,
    per `assess/evidence.py`. `stale` is set on the currently *approved*
    version, not the draft that created it, whenever a later evidence
    pack's hash no longer matches it (see `assess/evidence.py`'s
    `refresh_staleness`) — a future report layer must refuse to publish a
    stale approved assessment until it's re-reviewed.
    """

    __tablename__ = "assessments"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    #: 1, 2, 3, ... per campaign — never reused, never overwritten.
    version: Mapped[int] = mapped_column(Integer(), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    draft: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="draft")
    #: True when this version was produced by `lh assess edit`, not a
    #: fresh LLM draft — distinguishes a human-authored version in the
    #: audit trail from one the model produced unattended.
    edited_by_human: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    #: Only meaningful on a version whose `status == "approved"`: set when
    #: the campaign's evidence has changed since this version's
    #: `evidence_hash` was computed.
    stale: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    reviewer_notes: Mapped[str | None] = mapped_column(Text(), nullable=True)

    __table_args__ = (
        UniqueConstraint("campaign_id", "version", name="uq_assessments_campaign_version"),
        Index("ix_assessments_campaign_id", "campaign_id"),
        CheckConstraint(f"status IN ({_ASSESSMENT_STATUS_SQL})", name="ck_assessments_status"),
        # "Exactly one approved version per campaign" enforced at the
        # database level, not just in `assess/review.py`'s application
        # logic: a partial unique index over rows where status='approved'
        # allows unlimited draft/in_review/rejected rows per campaign but
        # a second concurrent approval of a different version for the
        # same campaign fails outright rather than racing.
        Index(
            "uq_assessments_one_approved_per_campaign",
            "campaign_id",
            unique=True,
            postgresql_where=text("status = 'approved'"),
            sqlite_where=text("status = 'approved'"),
        ),
    )


# --- Milestone 5: export -------------------------------------------------
#
# An append-only publish log, one row per `lh publish` run: which
# approved assessment version was published, under what TLP marking, and
# a content hash for every artifact produced (STIX bundle, MISP event,
# IOC feed entry, Markdown/PDF report) — so "what did we actually publish
# and when" is answerable without re-deriving it from files on disk.


class Publication(TimestampMixin, Base):
    """One `lh publish` run for one campaign."""

    __tablename__ = "publications"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    #: The specific approved assessment version this publish used —
    #: publishing again after a re-approval creates a new row, never
    #: rewrites this one.
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    published_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    tlp: Mapped[str] = mapped_column(String(20), nullable=False)
    #: {artifact_name: {"path": relative-path-str, "sha256": hex-digest}},
    #: e.g. {"stix_bundle": {...}, "misp_event": {...}, "feed_campaign": {...},
    #: "report_md": {...}, "report_pdf": {...}}. Which keys are present
    #: depends on what `lh publish` actually produced (e.g. no PDF if
    #: weasyprint isn't available).
    artifacts: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False, default=dict)

    __table_args__ = (
        Index("ix_publications_campaign_id", "campaign_id"),
        Index("ix_publications_assessment_id", "assessment_id"),
    )


# --- Config store ---------------------------------------------------------
#
# GUI/CLI-editable overrides for the config that otherwise lives in
# config/*.yaml files and .env — see `ledgerhound/config_store.py`. A row
# existing for a given key takes precedence over that domain's
# file/env default the moment it's written; deleting it (`lh config
# reset`) reverts to that default. `DATABASE_URL` and the logging
# settings are deliberately never part of this store — they're needed
# to reach this table (or configure logging) before it can be read.


class ConfigOverride(Base):
    """One config domain's current override value: `sources`,
    `providers`, `clustering`, or `runtime`. A natural string key, not a
    generated id — there's exactly one row per domain, ever."""

    __tablename__ = "config_overrides"

    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
