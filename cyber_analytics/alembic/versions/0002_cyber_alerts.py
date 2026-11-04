"""Create cyber_alerts table.

Revision ID: 0002_cyber_alerts
Revises: 0001_security_events
Create Date: 2026-11-04
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_cyber_alerts"
down_revision: Union[str, None] = "0001_security_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cyber_alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.String(length=128), nullable=True),
        sa.Column("ip_address", sa.String(length=128), nullable=True),
        sa.Column("camera_id", sa.String(length=64), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cyber_alerts_status_ts", "cyber_alerts", ["status", "created_at"])
    op.create_index("ix_cyber_alerts_severity_ts", "cyber_alerts", ["severity", "created_at"])
    op.create_index("ix_cyber_alerts_rule_ts", "cyber_alerts", ["rule_id", "created_at"])
    op.create_index("ix_cyber_alerts_cam_ts", "cyber_alerts", ["camera_id", "created_at"])
    op.create_index("ix_cyber_alerts_user_ts", "cyber_alerts", ["user_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_cyber_alerts_user_ts", table_name="cyber_alerts")
    op.drop_index("ix_cyber_alerts_cam_ts", table_name="cyber_alerts")
    op.drop_index("ix_cyber_alerts_rule_ts", table_name="cyber_alerts")
    op.drop_index("ix_cyber_alerts_severity_ts", table_name="cyber_alerts")
    op.drop_index("ix_cyber_alerts_status_ts", table_name="cyber_alerts")
    op.drop_table("cyber_alerts")
