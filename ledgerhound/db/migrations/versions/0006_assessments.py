"""assessments

Revision ID: 0006_assessments
Revises: 0005_campaigns
Create Date: 2026-09-02

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.types import GUID, JSONB, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0006_assessments"
down_revision: str | None = "0005_campaigns"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "assessments",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column("created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("campaign_id", GUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("prompt_version", sa.String(length=50), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("draft", JSONB(), nullable=False),
        sa.Column("status", sa.String(length=12), nullable=False),
        sa.Column("edited_by_human", sa.Boolean(), nullable=False),
        sa.Column("stale", sa.Boolean(), nullable=False),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("reviewed_at", UTCDateTime(), nullable=True),
        sa.Column("reviewer_notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["campaigns.id"], name="fk_assessments_campaign_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("campaign_id", "version", name="uq_assessments_campaign_version"),
        sa.CheckConstraint(
            "status IN ('draft', 'in_review', 'approved', 'rejected')",
            name="ck_assessments_status",
        ),
    )
    op.create_index("ix_assessments_campaign_id", "assessments", ["campaign_id"])
    # Exactly one approved version per campaign, enforced by the database
    # itself (a partial unique index), not just in assess/review.py.
    op.create_index(
        "uq_assessments_one_approved_per_campaign",
        "assessments",
        ["campaign_id"],
        unique=True,
        postgresql_where=sa.text("status = 'approved'"),
        sqlite_where=sa.text("status = 'approved'"),
    )


def downgrade() -> None:
    op.drop_table("assessments")
