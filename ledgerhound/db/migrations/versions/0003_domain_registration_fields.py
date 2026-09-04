"""domain_profiles: last-changed, status codes, registered flag, registration provider

Revision ID: 0003_domain_registration_fields
Revises: 0002_enrichment_projections
Create Date: 2026-09-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.types import JSONB, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0003_domain_registration_fields"
down_revision: str | None = "0002_enrichment_projections"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "domain_profiles", sa.Column("domain_updated_at", UTCDateTime(), nullable=True)
    )
    op.add_column("domain_profiles", sa.Column("registered", sa.Boolean(), nullable=True))
    op.add_column(
        "domain_profiles",
        sa.Column("status", JSONB(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "domain_profiles", sa.Column("registration_provider", sa.String(length=255), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("domain_profiles", "registration_provider")
    op.drop_column("domain_profiles", "status")
    op.drop_column("domain_profiles", "registered")
    op.drop_column("domain_profiles", "domain_updated_at")
