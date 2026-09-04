"""initial schema: sources, raw_reports, indicators, indicator_observations, enrichment, edges

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-02

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.models import EdgeRelation, IndicatorType, SourceType
from ledgerhound.db.types import GUID, JSONB, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "sources",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column(
            "created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "type",
            sa.Enum(SourceType, name="source_type", values_callable=lambda e: [m.value for m in e]),
            nullable=False,
        ),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("cadence_minutes", sa.Integer(), nullable=False),
        sa.Column("reliability_grade", sa.String(length=1), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "reliability_grade IN ('A', 'B', 'C', 'D', 'E', 'F')",
            name="ck_sources_reliability_grade",
        ),
        sa.UniqueConstraint("name", name="uq_sources_name"),
    )

    op.create_table(
        "raw_reports",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column(
            "created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("source_id", GUID(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("fetched_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name="fk_raw_reports_source_id", ondelete="CASCADE"
        ),
        sa.UniqueConstraint(
            "source_id", "content_hash", name="uq_raw_reports_source_content_hash"
        ),
    )
    op.create_index("ix_raw_reports_source_id", "raw_reports", ["source_id"])
    op.create_index("ix_raw_reports_content_hash", "raw_reports", ["content_hash"])

    op.create_table(
        "indicators",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column(
            "created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "type",
            sa.Enum(
                IndicatorType,
                name="indicator_type",
                values_callable=lambda e: [m.value for m in e],
            ),
            nullable=False,
        ),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("defanged_value", sa.String(length=2048), nullable=False),
        sa.Column("first_seen", UTCDateTime(), nullable=False),
        sa.Column("last_seen", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("type", "value", name="uq_indicators_type_value"),
    )
    op.create_index("ix_indicators_value", "indicators", ["value"])
    op.create_index("ix_indicators_type", "indicators", ["type"])

    op.create_table(
        "indicator_observations",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column(
            "created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("raw_report_id", GUID(), nullable=False),
        sa.Column("observed_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_indicator_observations_indicator_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["raw_report_id"],
            ["raw_reports.id"],
            name="fk_indicator_observations_raw_report_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "indicator_id",
            "raw_report_id",
            name="uq_indicator_observations_indicator_report",
        ),
    )
    op.create_index(
        "ix_indicator_observations_indicator_id", "indicator_observations", ["indicator_id"]
    )
    op.create_index(
        "ix_indicator_observations_raw_report_id", "indicator_observations", ["raw_report_id"]
    )

    op.create_table(
        "enrichment",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column(
            "created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("provider", sa.String(length=255), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("fetched_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_enrichment_indicator_id",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_enrichment_indicator_id", "enrichment", ["indicator_id"])

    op.create_table(
        "edges",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column(
            "created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("src_indicator_id", GUID(), nullable=False),
        sa.Column("dst_indicator_id", GUID(), nullable=False),
        sa.Column(
            "relation",
            sa.Enum(
                EdgeRelation, name="edge_relation", values_callable=lambda e: [m.value for m in e]
            ),
            nullable=False,
        ),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("evidence", JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["src_indicator_id"],
            ["indicators.id"],
            name="fk_edges_src_indicator_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["dst_indicator_id"],
            ["indicators.id"],
            name="fk_edges_dst_indicator_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "src_indicator_id", "dst_indicator_id", "relation", name="uq_edges_src_dst_relation"
        ),
        sa.CheckConstraint("src_indicator_id != dst_indicator_id", name="ck_edges_no_self_loop"),
    )
    op.create_index("ix_edges_src_indicator_id", "edges", ["src_indicator_id"])
    op.create_index("ix_edges_dst_indicator_id", "edges", ["dst_indicator_id"])


def downgrade() -> None:
    op.drop_table("edges")
    op.drop_table("enrichment")
    op.drop_table("indicator_observations")
    op.drop_table("indicators")
    op.drop_table("raw_reports")
    op.drop_table("sources")
    sa.Enum(name="edge_relation").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="indicator_type").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="source_type").drop(op.get_bind(), checkfirst=True)
