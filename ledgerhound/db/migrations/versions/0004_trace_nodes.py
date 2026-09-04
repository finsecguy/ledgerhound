"""trace_nodes: per-address hop/terminal-label data for a trace run

Milestone 2's `lh trace` computed this in memory to print it but never
persisted it. Milestone 3's `shares_cashout_path` relation needs it.

Revision ID: 0004_trace_nodes
Revises: 0003_domain_registration_fields
Create Date: 2026-09-03

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from ledgerhound.db.types import GUID, JSONB, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "0004_trace_nodes"
down_revision: str | None = "0003_domain_registration_fields"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "trace_nodes",
        sa.Column("id", GUID(), primary_key=True, default=uuid.uuid4, nullable=False),
        sa.Column("created_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("trace_id", GUID(), nullable=False),
        sa.Column("address", sa.String(length=255), nullable=False),
        sa.Column("hop", sa.Integer(), nullable=False),
        sa.Column("is_terminal", sa.Boolean(), nullable=False),
        sa.Column("terminal_reason", sa.String(length=20), nullable=True),
        sa.Column("labels", JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["trace_id"], ["traces.id"], name="fk_trace_nodes_trace_id", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("trace_id", "address", name="uq_trace_nodes_trace_address"),
    )
    op.create_index("ix_trace_nodes_trace_id", "trace_nodes", ["trace_id"])
    op.create_index("ix_trace_nodes_address", "trace_nodes", ["address"])


def downgrade() -> None:
    op.drop_table("trace_nodes")
