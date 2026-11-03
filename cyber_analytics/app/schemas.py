from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models import EventType


class SecurityEventIn(BaseModel):
    """Inbound event from another service (Flask model server, VMS backend, etc.)."""

    event_type: EventType
    user_id: str | None = None
    username_attempted: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    camera_id: str | None = None
    video_id: str | None = None
    success: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    event_type: str
    user_id: str | None
    username_attempted: str | None
    ip_address: str
    user_agent: str | None
    device_fingerprint: str
    camera_id: str | None
    video_id: str | None
    success: bool
    metadata: dict[str, Any] | None = None

    @classmethod
    def from_row(cls, row: Any) -> "SecurityEventOut":
        return cls(
            id=row.id,
            timestamp=row.timestamp,
            event_type=row.event_type,
            user_id=row.user_id,
            username_attempted=row.username_attempted,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            device_fingerprint=row.device_fingerprint,
            camera_id=row.camera_id,
            video_id=row.video_id,
            success=row.success,
            metadata=row.event_metadata,
        )
