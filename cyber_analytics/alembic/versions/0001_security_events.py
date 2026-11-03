"""Create security_events table.

Revision ID: 0001_security_events
Revises:
Create Date: 2026-11-03
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_security_events"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=128), nullable=True),
        sa.Column("username_attempted", sa.String(length=256), nullable=True),
        sa.Column("ip_address", sa.String(length=128), nullable=False),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("device_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("camera_id", sa.String(length=64), nullable=True),
        sa.Column("video_id", sa.String(length=64), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_events_type_ts", "security_events", ["event_type", "timestamp"])
    op.create_index("ix_security_events_ip_ts", "security_events", ["ip_address", "timestamp"])
    op.create_index("ix_security_events_user_ts", "security_events", ["user_id", "timestamp"])


def downgrade() -> None:
    op.drop_index("ix_security_events_user_ts", table_name="security_events")
    op.drop_index("ix_security_events_ip_ts", table_name="security_events")
    op.drop_index("ix_security_events_type_ts", table_name="security_events")
    op.drop_table("security_events")
