from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.detection.alerts_store import alert_store
from app.detection.rules import Alert, Severity, evaluate_rules
from app.models import CyberAlert, EventType, SecurityEvent
from app.privacy import device_fingerprint, hmac_hex, mask_ip, sanitize_metadata


def persist_alert(db: Session, alert: Alert) -> CyberAlert:
    """Persist an in-memory Alert dataclass instance into the cyber_alerts table."""
    severity_val = alert.severity.value if isinstance(alert.severity, Severity) else str(alert.severity)
    row = CyberAlert(
        rule_id=alert.rule_id,
        severity=severity_val,
        status="open",
        entity_type=alert.entity_type,
        entity_id=alert.entity_id,
        user_id=alert.user,
        ip_address=alert.ip,
        camera_id=alert.camera,
        confidence=float(alert.confidence),
        explanation=alert.reason,
        raw_evidence=alert.evidence,
        created_at=alert.created_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def log_security_event(
    db: Session,
    *,
    event_type: EventType | str,
    ip_address: str,
    user_agent: str | None = None,
    user_id: str | None = None,
    username_attempted: str | None = None,
    camera_id: str | None = None,
    video_id: str | None = None,
    success: bool = True,
    metadata: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
    run_detection: bool = True,
) -> SecurityEvent:
    """Persist one security event. IPs are HMAC'd; secrets in metadata are stripped.

    Optionally evaluates detection rules and stores any triggered alerts.
    """
    event_type_value = event_type.value if isinstance(event_type, EventType) else str(event_type)
    ua = (user_agent or "")[:512]
    raw_ip = ip_address or "unknown"
    extra = sanitize_metadata(metadata)
    extra.setdefault("masked_ip", mask_ip(raw_ip))

    row = SecurityEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        event_type=event_type_value,
        user_id=user_id,
        username_attempted=username_attempted,
        ip_address=hmac_hex(raw_ip, settings.cyber_hmac_secret),
        user_agent=ua or None,
        device_fingerprint=device_fingerprint(ua, raw_ip),
        camera_id=camera_id,
        video_id=video_id,
        success=success,
        event_metadata=extra,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    if run_detection:
        alerts = evaluate_rules(db, row)
        if alerts:
            alert_store.add_many(alerts)
            for a in alerts:
                persist_alert(db, a)
        setattr(row, "_triggered_alerts", alerts)
    else:
        setattr(row, "_triggered_alerts", [])

    return row
