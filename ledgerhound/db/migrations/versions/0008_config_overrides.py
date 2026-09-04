"""config_overrides

Revision ID: 0008_config_overrides
Revises: 0007_publications
Create Date: 2026-09-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.types import JSONB, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0008_config_overrides"
down_revision: str | None = "0007_publications"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "config_overrides",
        sa.Column("key", sa.String(length=50), primary_key=True),
        sa.Column("value", JSONB(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("config_overrides")
