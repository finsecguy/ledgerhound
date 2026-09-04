"""campaigns, campaign_members, campaign_events

Revision ID: 0005_campaigns
Revises: 0004_trace_nodes
Create Date: 2026-09-03

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.types import GUID, JSONB, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0005_campaigns"
down_revision: str | None = "0004_trace_nodes"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column("created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("code", sa.String(length=20), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("relation_types", JSONB(), nullable=False),
        sa.Column("first_seen", UTCDateTime(), nullable=False),
        sa.Column("last_seen", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("code", name="uq_campaigns_code"),
        sa.CheckConstraint("status IN ('active', 'dormant')", name="ck_campaigns_status"),
    )

    op.create_table(
        "campaign_members",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column("created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("campaign_id", GUID(), nullable=False),
        sa.Column("indicator_id", GUID(), nullable=False),
        sa.Column("joined_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["campaigns.id"], name="fk_campaign_members_campaign_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"], ["indicators.id"], name="fk_campaign_members_indicator_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "campaign_id", "indicator_id", name="uq_campaign_members_campaign_indicator"
        ),
    )
    op.create_index("ix_campaign_members_campaign_id", "campaign_members", ["campaign_id"])
    op.create_index("ix_campaign_members_indicator_id", "campaign_members", ["indicator_id"])

    op.create_table(
        "campaign_events",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column("created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("campaign_id", GUID(), nullable=False),
        sa.Column("event_type", sa.String(length=10), nullable=False),
        sa.Column("occurred_at", UTCDateTime(), nullable=False),
        sa.Column("related_campaign_codes", JSONB(), nullable=False),
        sa.Column("members_before", JSONB(), nullable=False),
        sa.Column("members_after", JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["campaigns.id"], name="fk_campaign_events_campaign_id",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "event_type IN ('merge', 'split')", name="ck_campaign_events_event_type"
        ),
    )
    op.create_index("ix_campaign_events_campaign_id", "campaign_events", ["campaign_id"])


def downgrade() -> None:
    op.drop_table("campaign_events")
    op.drop_table("campaign_members")
    op.drop_table("campaigns")
