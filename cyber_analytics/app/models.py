from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, Uuid


class Base(DeclarativeBase):
    pass


class EventType(str, enum.Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    VIDEO_VIEW = "VIDEO_VIEW"
    VIDEO_DOWNLOAD = "VIDEO_DOWNLOAD"
    VIDEO_UPLOAD = "VIDEO_UPLOAD"
    VIDEO_DELETE = "VIDEO_DELETE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CAMERA_HEARTBEAT = "CAMERA_HEARTBEAT"
    CAMERA_OFFLINE = "CAMERA_OFFLINE"
    ROLE_CHANGE = "ROLE_CHANGE"


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_type_ts", "event_type", "timestamp"),
        Index("ix_security_events_ip_ts", "ip_address", "timestamp"),
        Index("ix_security_events_user_ts", "user_id", "timestamp"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    username_attempted: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(128), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    device_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    camera_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    video_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    event_metadata: Mapped[dict | None] = mapped_column(
        "metadata", JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
