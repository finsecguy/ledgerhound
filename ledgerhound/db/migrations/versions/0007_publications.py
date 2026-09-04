"""publications

Revision ID: 0007_publications
Revises: 0006_assessments
Create Date: 2026-09-04

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.types import GUID, JSONB, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0007_publications"
down_revision: str | None = "0006_assessments"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "publications",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column("created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("campaign_id", GUID(), nullable=False),
        sa.Column("assessment_id", GUID(), nullable=False),
        sa.Column("published_at", UTCDateTime(), nullable=False),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("artifacts", JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["campaigns.id"], name="fk_publications_campaign_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["assessments.id"], name="fk_publications_assessment_id",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_publications_campaign_id", "publications", ["campaign_id"])
    op.create_index("ix_publications_assessment_id", "publications", ["assessment_id"])


def downgrade() -> None:
    op.drop_table("publications")
