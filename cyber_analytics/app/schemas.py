from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models import AlertSeverity, AlertStatus, EventType


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


class CyberAlertOut(BaseModel):
    """Cybersecurity Alert output schema."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    rule_id: str
    severity: str
    status: str
    entity_type: str
    entity_id: str
    user_id: str | None = None
    ip_address: str | None = None
    camera_id: str | None = None
    confidence: float
    explanation: str
    evidence: dict[str, Any] | None = None

    @classmethod
    def from_row(cls, row: Any) -> "CyberAlertOut":
        return cls(
            id=row.id,
            created_at=row.created_at,
            rule_id=row.rule_id,
            severity=row.severity,
            status=row.status,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            user_id=row.user_id,
            ip_address=row.ip_address,
            camera_id=row.camera_id,
            confidence=round(row.confidence, 4),
            explanation=row.explanation,
            evidence=row.raw_evidence,
        )


class CyberAlertStatusUpdate(BaseModel):
    """Payload to update an alert's status (open -> acknowledged -> resolved)."""

    status: AlertStatus


class AlertSummaryStats(BaseModel):
    """Aggregated alert metrics for dashboards and health scoring."""

    total_alerts: int
    open_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    by_severity: dict[str, int]
    by_rule: dict[str, int]
    by_status: dict[str, int]
    top_suspicious_ips: list[dict[str, Any]]
    top_suspicious_users: list[dict[str, Any]]


class CyberSignalResponse(BaseModel):
    """Real-time cyber telemetry signals for visual threat risk correlation."""

    target_camera: str | None
    target_user: str | None
    window_seconds: int
    cyber_threat_score: float  # [0.0, 1.0]
    has_active_cyber_threat: bool
    active_alerts: list[CyberAlertOut]
    indicators: list[str]
