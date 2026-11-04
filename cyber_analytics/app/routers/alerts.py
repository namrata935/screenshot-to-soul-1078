"""FastAPI endpoints for Cybersecurity Alerts management, metrics, and correlation signals."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import AlertSeverity, AlertStatus, CyberAlert, SecurityEvent
from app.schemas import (
    AlertSummaryStats,
    CyberAlertOut,
    CyberAlertStatusUpdate,
    CyberSignalResponse,
)

router = APIRouter(prefix="/api/v1", tags=["alerts"])


def get_cyber_signals(
    db: Session,
    *,
    camera_id: str | None = None,
    user_id: str | None = None,
    window_seconds: int = 600,
) -> CyberSignalResponse:
    """Fetch recent cyber telemetry signals and calculate threat score for visual AI correlation.

    Used by the risk-scoring service to correlate visual threat events with cyber anomalies.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

    # 1. Fetch active alerts in the window
    alert_stmt = select(CyberAlert).where(
        CyberAlert.created_at >= cutoff,
        CyberAlert.status != AlertStatus.RESOLVED.value,
    )

    if camera_id and user_id:
        alert_stmt = alert_stmt.where(
            or_(CyberAlert.camera_id == camera_id, CyberAlert.user_id == user_id)
        )
    elif camera_id:
        alert_stmt = alert_stmt.where(CyberAlert.camera_id == camera_id)
    elif user_id:
        alert_stmt = alert_stmt.where(CyberAlert.user_id == user_id)

    alerts = list(db.scalars(alert_stmt.order_by(CyberAlert.created_at.desc())))

    # 2. Score calculation based on alerts
    threat_score = 0.0
    indicators: list[str] = []

    for a in alerts:
        sev = a.severity.lower()
        if sev == "critical":
            threat_score += 0.60
            indicators.append(f"Critical Cyber Alert: {a.rule_id} ({a.explanation})")
        elif sev == "high":
            threat_score += 0.40
            indicators.append(f"High Cyber Alert: {a.rule_id} ({a.explanation})")
        elif sev == "medium":
            threat_score += 0.20
            indicators.append(f"Medium Cyber Alert: {a.rule_id}")
        else:
            threat_score += 0.10

    # 3. Check for raw security event anomalies (e.g. permission denied or failed logins)
    event_stmt = select(SecurityEvent).where(
        SecurityEvent.timestamp >= cutoff,
        SecurityEvent.success.is_(False),
    )
    if camera_id:
        event_stmt = event_stmt.where(SecurityEvent.camera_id == camera_id)
    elif user_id:
        event_stmt = event_stmt.where(
            or_(SecurityEvent.user_id == user_id, SecurityEvent.username_attempted == user_id)
        )

    failed_events = list(db.scalars(event_stmt))
    if failed_events:
        threat_score += min(len(failed_events) * 0.05, 0.25)
        indicators.append(f"{len(failed_events)} failed security events observed in time window")

    final_score = round(min(threat_score, 1.0), 3)

    return CyberSignalResponse(
        target_camera=camera_id,
        target_user=user_id,
        window_seconds=window_seconds,
        cyber_threat_score=final_score,
        has_active_cyber_threat=final_score >= 0.40,
        active_alerts=[CyberAlertOut.from_row(a) for a in alerts],
        indicators=indicators,
    )


def _clean_param(param: Any) -> str | None:
    if param is None:
        return None
    if hasattr(param, "default"):
        return None if param.default is None else str(param.default)
    return str(param)


@router.get(
    "/alerts",
    response_model=list[CyberAlertOut],
    dependencies=[Depends(require_admin)],
)
def list_alerts(
    db: Session = Depends(get_db),
    status: str | None = Query(default=None, description="Filter by status (open, acknowledged, resolved)"),
    severity: str | None = Query(default=None, description="Filter by severity (low, medium, high, critical)"),
    rule_id: str | None = Query(default=None, description="Filter by rule or ML identifier"),
    user_id: str | None = Query(default=None, description="Filter by affected user ID"),
    camera_id: str | None = Query(default=None, description="Filter by camera ID"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List and filter cybersecurity alerts with pagination."""
    limit_val = int(limit.default if hasattr(limit, "default") else limit)
    offset_val = int(offset.default if hasattr(offset, "default") else offset)

    status_val = _clean_param(status)
    severity_val = _clean_param(severity)
    rule_id_val = _clean_param(rule_id)
    user_id_val = _clean_param(user_id)
    camera_id_val = _clean_param(camera_id)

    stmt = select(CyberAlert).order_by(CyberAlert.created_at.desc()).offset(offset_val).limit(limit_val)

    if status_val:
        stmt = stmt.where(CyberAlert.status == status_val)
    if severity_val:
        stmt = stmt.where(CyberAlert.severity == severity_val)
    if rule_id_val:
        stmt = stmt.where(CyberAlert.rule_id == rule_id_val)
    if user_id_val:
        stmt = stmt.where(CyberAlert.user_id == user_id_val)
    if camera_id_val:
        stmt = stmt.where(CyberAlert.camera_id == camera_id_val)

    rows = db.scalars(stmt)
    return [CyberAlertOut.from_row(r) for r in rows]


@router.get(
    "/alerts/{alert_id}",
    response_model=CyberAlertOut,
    dependencies=[Depends(require_admin)],
)
def get_alert(alert_id: uuid.UUID, db: Session = Depends(get_db)):
    """Fetch details for a single cybersecurity alert."""
    alert = db.get(CyberAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return CyberAlertOut.from_row(alert)


@router.patch(
    "/alerts/{alert_id}/status",
    response_model=CyberAlertOut,
    dependencies=[Depends(require_admin)],
)
def update_alert_status(
    alert_id: uuid.UUID,
    body: CyberAlertStatusUpdate,
    db: Session = Depends(get_db),
):
    """Acknowledge or resolve an active alert."""
    alert = db.get(CyberAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = body.status.value if isinstance(body.status, AlertStatus) else str(body.status)
    db.commit()
    db.refresh(alert)
    return CyberAlertOut.from_row(alert)


@router.get(
    "/alerts/stats/summary",
    response_model=AlertSummaryStats,
    dependencies=[Depends(require_admin)],
)
def get_alert_summary(
    db: Session = Depends(get_db),
    days: int = Query(default=7, ge=1, le=90),
):
    """Get aggregated metrics and counts by severity, rule, and status for dashboard display."""
    days_val = int(days.default if hasattr(days, "default") else days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_val)

    # All alerts within the time window
    stmt = select(CyberAlert).where(CyberAlert.created_at >= cutoff)
    alerts = list(db.scalars(stmt))

    total = len(alerts)
    open_count = sum(1 for a in alerts if a.status == "open")
    ack_count = sum(1 for a in alerts if a.status == "acknowledged")
    res_count = sum(1 for a in alerts if a.status == "resolved")

    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    by_status: dict[str, int] = {}
    ip_counts: dict[str, int] = {}
    user_counts: dict[str, int] = {}

    for a in alerts:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
        by_status[a.status] = by_status.get(a.status, 0) + 1
        if a.ip_address:
            ip_counts[a.ip_address] = ip_counts.get(a.ip_address, 0) + 1
        if a.user_id:
            user_counts[a.user_id] = user_counts.get(a.user_id, 0) + 1

    top_ips = [
        {"ip_address": ip, "alert_count": cnt}
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]
    top_users = [
        {"user_id": u, "alert_count": cnt}
        for u, cnt in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    return AlertSummaryStats(
        total_alerts=total,
        open_alerts=open_count,
        acknowledged_alerts=ack_count,
        resolved_alerts=res_count,
        by_severity=by_severity,
        by_rule=by_rule,
        by_status=by_status,
        top_suspicious_ips=top_ips,
        top_suspicious_users=top_users,
    )


@router.get(
    "/signals/correlate",
    response_model=CyberSignalResponse,
    dependencies=[Depends(require_admin)],
)
def correlate_signals(
    db: Session = Depends(get_db),
    camera_id: str | None = Query(default=None, description="Camera to check for cyber threats"),
    user_id: str | None = Query(default=None, description="User to check for cyber threats"),
    window_seconds: int = Query(default=600, ge=60, le=86400, description="Window size in seconds (default: 10m)"),
):
    """Correlate cyber threat telemetry for a camera or user to merge with visual AI detection."""
    win_val = int(window_seconds.default if hasattr(window_seconds, "default") else window_seconds)
    return get_cyber_signals(db, camera_id=camera_id, user_id=user_id, window_seconds=win_val)
