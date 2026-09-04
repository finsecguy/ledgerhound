"""enrichment projection tables

address_profiles, address_counterparties, address_labels, domain_profiles,
domain_certs, traces, trace_edges

Revision ID: 0002_enrichment_projections
Revises: 0001_initial_schema
Create Date: 2026-09-02

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.types import GUID, JSONB, PreciseNumeric, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0002_enrichment_projections"
down_revision: str | None = "0001_initial_schema"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def _timestamp_columns() -> list[sa.Column[Any]]:
    return [
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column(
            "created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "address_profiles",
        *_timestamp_columns(),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("chain", sa.String(length=10), nullable=False),
        sa.Column("first_seen_onchain", UTCDateTime(), nullable=True),
        sa.Column("last_seen_onchain", UTCDateTime(), nullable=True),
        sa.Column("tx_count", sa.Integer(), nullable=False),
        sa.Column("total_received", PreciseNumeric(), nullable=False),
        sa.Column("total_sent", PreciseNumeric(), nullable=False),
        sa.Column("current_balance", PreciseNumeric(), nullable=False),
        sa.Column("decimals", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=255), nullable=False),
        sa.Column("enriched_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_address_profiles_indicator_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("indicator_id", name="uq_address_profiles_indicator_id"),
        sa.CheckConstraint(
            "chain IN ('btc', 'eth', 'tron', 'sol')", name="ck_address_profiles_chain"
        ),
    )

    op.create_table(
        "address_counterparties",
        *_timestamp_columns(),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("counterparty_address", sa.String(length=255), nullable=False),
        sa.Column("direction", sa.String(length=3), nullable=False),
        sa.Column("tx_count", sa.Integer(), nullable=False),
        sa.Column("total_value", PreciseNumeric(), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_address_counterparties_indicator_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "indicator_id",
            "counterparty_address",
            "direction",
            name="uq_address_counterparties_indicator_addr_dir",
        ),
        sa.CheckConstraint(
            "direction IN ('in', 'out')", name="ck_address_counterparties_direction"
        ),
    )
    op.create_index(
        "ix_address_counterparties_indicator_id", "address_counterparties", ["indicator_id"]
    )
    op.create_index(
        "ix_address_counterparties_counterparty_address",
        "address_counterparties",
        ["counterparty_address"],
    )

    op.create_table(
        "address_labels",
        *_timestamp_columns(),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("label_type", sa.String(length=20), nullable=False),
        sa.Column("source", sa.String(length=500), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_address_labels_indicator_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "indicator_id", "label", "source", name="uq_address_labels_indicator_label_source"
        ),
        sa.CheckConstraint(
            "label_type IN ('exchange', 'mixer', 'bridge', 'sanctioned', 'scam')",
            name="ck_address_labels_label_type",
        ),
    )
    op.create_index("ix_address_labels_indicator_id", "address_labels", ["indicator_id"])

    op.create_table(
        "domain_profiles",
        *_timestamp_columns(),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("registrar", sa.String(length=255), nullable=True),
        sa.Column("domain_created_at", UTCDateTime(), nullable=True),
        sa.Column("domain_expires_at", UTCDateTime(), nullable=True),
        sa.Column("registrant_country", sa.String(length=2), nullable=True),
        sa.Column("registrant_redacted", sa.Boolean(), nullable=False),
        sa.Column("ns_records", JSONB(), nullable=False),
        sa.Column("asn", sa.String(length=32), nullable=True),
        sa.Column("nxdomain", sa.Boolean(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("http_server_header", sa.String(length=255), nullable=True),
        sa.Column("body_hash", sa.String(length=64), nullable=True),
        sa.Column("favicon_hash", sa.String(length=64), nullable=True),
        sa.Column("enriched_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_domain_profiles_indicator_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("indicator_id", name="uq_domain_profiles_indicator_id"),
    )
    op.create_index("ix_domain_profiles_asn", "domain_profiles", ["asn"])
    op.create_index("ix_domain_profiles_registrar", "domain_profiles", ["registrar"])
    op.create_index("ix_domain_profiles_body_hash", "domain_profiles", ["body_hash"])
    op.create_index("ix_domain_profiles_favicon_hash", "domain_profiles", ["favicon_hash"])

    op.create_table(
        "domain_certs",
        *_timestamp_columns(),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("san", sa.String(length=500), nullable=False),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("not_before", UTCDateTime(), nullable=False),
        sa.Column("not_after", UTCDateTime(), nullable=False),
        sa.Column("serial_number", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_domain_certs_indicator_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "indicator_id", "serial_number", "san", name="uq_domain_certs_indicator_serial_san"
        ),
    )
    op.create_index("ix_domain_certs_indicator_id", "domain_certs", ["indicator_id"])
    op.create_index("ix_domain_certs_san", "domain_certs", ["san"])

    op.create_table(
        "traces",
        *_timestamp_columns(),
        sa.Column("root_indicator_id", GUID(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("run_at", UTCDateTime(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("summary", JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["root_indicator_id"],
            ["indicators.id"],
            name="fk_traces_root_indicator_id",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_traces_root_indicator_id", "traces", ["root_indicator_id"])

    op.create_table(
        "trace_edges",
        *_timestamp_columns(),
        sa.Column("trace_id", GUID(), nullable=False),
        sa.Column("src_address", sa.String(length=255), nullable=False),
        sa.Column("dst_address", sa.String(length=255), nullable=False),
        sa.Column("hop", sa.Integer(), nullable=False),
        sa.Column("value", PreciseNumeric(), nullable=False),
        sa.Column("tx_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["trace_id"], ["traces.id"], name="fk_trace_edges_trace_id", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_trace_edges_trace_id", "trace_edges", ["trace_id"])
    op.create_index("ix_trace_edges_src_address", "trace_edges", ["src_address"])
    op.create_index("ix_trace_edges_dst_address", "trace_edges", ["dst_address"])


def downgrade() -> None:
    op.drop_table("trace_edges")
    op.drop_table("traces")
    op.drop_table("domain_certs")
    op.drop_table("domain_profiles")
    op.drop_table("address_labels")
    op.drop_table("address_counterparties")
    op.drop_table("address_profiles")
