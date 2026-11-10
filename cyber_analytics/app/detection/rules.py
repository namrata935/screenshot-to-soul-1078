"""Rule-based cybersecurity detection engine for the Secure VMS platform.

Independent, unit-testable rules detecting suspicious platform behavior:
1. Brute force: >5 failed logins from one IP or against one account in 60s.
2. Credential stuffing: one IP failing logins across 3+ distinct usernames.
3. Impossible access: same user active from 2+ distinct IPs within short window.
4. Mass export: user views/downloads an unusually high number of videos in 10m.
5. Privilege abuse: repeated PERMISSION_DENIED by one user.
6. Camera tampering: camera heartbeat missing for N minutes or sudden feed stop.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings, settings
from app.models import EventType, SecurityEvent


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Detection alert object returned by rules and the anomaly engine."""

    rule_id: str
    severity: Severity | str
    entity_type: str  # "user", "ip", "camera"
    entity_id: str
    evidence: dict[str, Any]
    reason: str
    confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def user(self) -> str | None:
        return self.entity_id if self.entity_type == "user" else self.evidence.get("user_id")

    @property
    def ip(self) -> str | None:
        return self.entity_id if self.entity_type == "ip" else self.evidence.get("ip_address")

    @property
    def camera(self) -> str | None:
        return self.entity_id if self.entity_type == "camera" else self.evidence.get("camera_id")

    def to_dict(self) -> dict[str, Any]:
        severity_val = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        return {
            "rule_id": self.rule_id,
            "severity": severity_val,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "evidence": self.evidence,
            "reason": self.reason,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "user": self.user,
            "ip": self.ip,
            "camera": self.camera,
        }


def _norm_ts(dt: datetime) -> datetime:
    """Ensure datetime has UTC timezone."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def check_brute_force(
    db: Session,
    event: SecurityEvent,
    *,
    window_seconds: int | None = None,
    threshold: int | None = None,
    cfg: Settings | None = None,
) -> Alert | None:
    """Rule 1: >5 failed logins from one IP or against one account in 60s."""
    if event.event_type != EventType.LOGIN_FAILED.value and event.event_type != "LOGIN_FAILED":
        return None

    app_cfg = cfg or settings
    win_sec = window_seconds if window_seconds is not None else app_cfg.rule_brute_force_window_seconds
    thresh = threshold if threshold is not None else app_cfg.rule_brute_force_threshold

    event_ts = _norm_ts(event.timestamp)
    start_ts = event_ts - timedelta(seconds=win_sec)

    # Check 1: failed logins from same IP
    ip_stmt = select(func.count(SecurityEvent.id)).where(
        SecurityEvent.event_type == EventType.LOGIN_FAILED.value,
        SecurityEvent.ip_address == event.ip_address,
        SecurityEvent.timestamp >= start_ts,
        SecurityEvent.timestamp <= event_ts,
    )
    ip_failed_count = db.scalar(ip_stmt) or 0

    if ip_failed_count > thresh:
        return Alert(
            rule_id="RULE_BRUTE_FORCE",
            severity=Severity.HIGH,
            entity_type="ip",
            entity_id=event.ip_address,
            evidence={
                "ip_address": event.ip_address,
                "target_type": "source_ip",
                "failed_count": ip_failed_count,
                "threshold": thresh,
                "window_seconds": win_sec,
                "username_attempted": event.username_attempted,
            },
            reason=(
                f"Brute force detected: {ip_failed_count} failed logins from IP "
                f"within {win_sec}s (threshold > {thresh})."
            ),
            created_at=event_ts,
        )

    # Check 2: failed logins against the same account (username or user_id)
    target_username = event.username_attempted or event.user_id
    if target_username:
        user_stmt = select(func.count(SecurityEvent.id)).where(
            SecurityEvent.event_type == EventType.LOGIN_FAILED.value,
            (SecurityEvent.username_attempted == target_username) | (SecurityEvent.user_id == target_username),
            SecurityEvent.timestamp >= start_ts,
            SecurityEvent.timestamp <= event_ts,
        )
        user_failed_count = db.scalar(user_stmt) or 0

        if user_failed_count > thresh:
            return Alert(
                rule_id="RULE_BRUTE_FORCE",
                severity=Severity.HIGH,
                entity_type="user",
                entity_id=target_username,
                evidence={
                    "username_attempted": target_username,
                    "target_type": "account",
                    "failed_count": user_failed_count,
                    "threshold": thresh,
                    "window_seconds": win_sec,
                    "last_ip": event.ip_address,
                },
                reason=(
                    f"Brute force detected: {user_failed_count} failed logins targeting account "
                    f"'{target_username}' within {win_sec}s (threshold > {thresh})."
                ),
                created_at=event_ts,
            )

    return None


def check_credential_stuffing(
    db: Session,
    event: SecurityEvent,
    *,
    window_seconds: int | None = None,
    threshold_usernames: int | None = None,
    cfg: Settings | None = None,
) -> Alert | None:
    """Rule 2: one IP failing logins across 3+ different usernames."""
    if event.event_type != EventType.LOGIN_FAILED.value and event.event_type != "LOGIN_FAILED":
        return None

    app_cfg = cfg or settings
    win_sec = (
        window_seconds
        if window_seconds is not None
        else app_cfg.rule_credential_stuffing_window_seconds
    )
    thresh = (
        threshold_usernames
        if threshold_usernames is not None
        else app_cfg.rule_credential_stuffing_threshold_usernames
    )

    event_ts = _norm_ts(event.timestamp)
    start_ts = event_ts - timedelta(seconds=win_sec)

    stmt = (
        select(SecurityEvent.username_attempted)
        .where(
            SecurityEvent.event_type == EventType.LOGIN_FAILED.value,
            SecurityEvent.ip_address == event.ip_address,
            SecurityEvent.timestamp >= start_ts,
            SecurityEvent.timestamp <= event_ts,
            SecurityEvent.username_attempted.is_not(None),
        )
        .distinct()
    )
    unique_usernames = {u for u in db.scalars(stmt) if u}

    if len(unique_usernames) >= thresh:
        return Alert(
            rule_id="RULE_CREDENTIAL_STUFFING",
            severity=Severity.HIGH,
            entity_type="ip",
            entity_id=event.ip_address,
            evidence={
                "ip_address": event.ip_address,
                "unique_usernames_count": len(unique_usernames),
                "distinct_usernames": sorted(list(unique_usernames)),
                "threshold": thresh,
                "window_seconds": win_sec,
            },
            reason=(
                f"Credential stuffing detected: IP failed logins across {len(unique_usernames)} "
                f"different usernames within {win_sec}s (threshold >= {thresh})."
            ),
            created_at=event_ts,
        )

    return None


def check_impossible_access(
    db: Session,
    event: SecurityEvent,
    *,
    window_seconds: int | None = None,
    cfg: Settings | None = None,
) -> Alert | None:
    """Rule 3: same user active from 2 distinct IPs within a short window."""
    if not event.user_id or not event.success:
        return None

    app_cfg = cfg or settings
    win_sec = (
        window_seconds
        if window_seconds is not None
        else app_cfg.rule_impossible_access_window_seconds
    )

    event_ts = _norm_ts(event.timestamp)
    start_ts = event_ts - timedelta(seconds=win_sec)

    stmt = (
        select(SecurityEvent.ip_address)
        .where(
            SecurityEvent.user_id == event.user_id,
            SecurityEvent.success.is_(True),
            SecurityEvent.timestamp >= start_ts,
            SecurityEvent.timestamp <= event_ts,
        )
        .distinct()
    )
    distinct_ips = {ip for ip in db.scalars(stmt) if ip}

    if len(distinct_ips) >= 2:
        return Alert(
            rule_id="RULE_IMPOSSIBLE_ACCESS",
            severity=Severity.CRITICAL,
            entity_type="user",
            entity_id=event.user_id,
            evidence={
                "user_id": event.user_id,
                "current_ip": event.ip_address,
                "distinct_ips": sorted(list(distinct_ips)),
                "distinct_ip_count": len(distinct_ips),
                "window_seconds": win_sec,
            },
            reason=(
                f"Impossible access detected: user '{event.user_id}' was active from "
                f"{len(distinct_ips)} distinct IPs within {win_sec}s."
            ),
            created_at=event_ts,
        )

    return None


def check_mass_export(
    db: Session,
    event: SecurityEvent,
    *,
    window_seconds: int | None = None,
    threshold: int | None = None,
    cfg: Settings | None = None,
) -> Alert | None:
    """Rule 4: user views/downloads an unusually high number of videos in 10 min."""
    export_types = {
        EventType.VIDEO_VIEW.value,
        EventType.VIDEO_DOWNLOAD.value,
        "VIDEO_VIEW",
        "VIDEO_DOWNLOAD",
    }
    if event.event_type not in export_types or not event.user_id or not event.success:
        return None

    app_cfg = cfg or settings
    win_sec = (
        window_seconds
        if window_seconds is not None
        else app_cfg.rule_mass_export_window_seconds
    )
    thresh = threshold if threshold is not None else app_cfg.rule_mass_export_threshold

    event_ts = _norm_ts(event.timestamp)
    start_ts = event_ts - timedelta(seconds=win_sec)

    stmt = select(SecurityEvent).where(
        SecurityEvent.user_id == event.user_id,
        SecurityEvent.event_type.in_([EventType.VIDEO_VIEW.value, EventType.VIDEO_DOWNLOAD.value]),
        SecurityEvent.success.is_(True),
        SecurityEvent.timestamp >= start_ts,
        SecurityEvent.timestamp <= event_ts,
    )
    records = list(db.scalars(stmt))
    count = len(records)

    if count > thresh:
        distinct_videos = {r.video_id for r in records if r.video_id}
        return Alert(
            rule_id="RULE_MASS_EXPORT",
            severity=Severity.HIGH,
            entity_type="user",
            entity_id=event.user_id,
            evidence={
                "user_id": event.user_id,
                "video_access_count": count,
                "unique_videos_count": len(distinct_videos),
                "threshold": thresh,
                "window_seconds": win_sec,
            },
            reason=(
                f"Mass export detected: user '{event.user_id}' accessed {count} videos "
                f"within {win_sec // 60}m (threshold > {thresh})."
            ),
            created_at=event_ts,
        )

    return None


def check_privilege_abuse(
    db: Session,
    event: SecurityEvent,
    *,
    window_seconds: int | None = None,
    threshold: int | None = None,
    cfg: Settings | None = None,
) -> Alert | None:
    """Rule 5: repeated PERMISSION_DENIED by one user."""
    if event.event_type != EventType.PERMISSION_DENIED.value and event.event_type != "PERMISSION_DENIED":
        return None

    app_cfg = cfg or settings
    win_sec = (
        window_seconds
        if window_seconds is not None
        else app_cfg.rule_privilege_abuse_window_seconds
    )
    thresh = (
        threshold
        if threshold is not None
        else app_cfg.rule_privilege_abuse_threshold
    )

    event_ts = _norm_ts(event.timestamp)
    start_ts = event_ts - timedelta(seconds=win_sec)

    target_user = event.user_id
    if target_user:
        stmt = select(func.count(SecurityEvent.id)).where(
            SecurityEvent.event_type == EventType.PERMISSION_DENIED.value,
            SecurityEvent.user_id == target_user,
            SecurityEvent.timestamp >= start_ts,
            SecurityEvent.timestamp <= event_ts,
        )
        count = db.scalar(stmt) or 0
        entity_type = "user"
        entity_id = target_user
    else:
        stmt = select(func.count(SecurityEvent.id)).where(
            SecurityEvent.event_type == EventType.PERMISSION_DENIED.value,
            SecurityEvent.ip_address == event.ip_address,
            SecurityEvent.timestamp >= start_ts,
            SecurityEvent.timestamp <= event_ts,
        )
        count = db.scalar(stmt) or 0
        entity_type = "ip"
        entity_id = event.ip_address

    if count >= thresh:
        return Alert(
            rule_id="RULE_PRIVILEGE_ABUSE",
            severity=Severity.MEDIUM,
            entity_type=entity_type,
            entity_id=entity_id,
            evidence={
                "target_entity": entity_id,
                "denied_count": count,
                "threshold": thresh,
                "window_seconds": win_sec,
                "ip_address": event.ip_address,
            },
            reason=(
                f"Privilege abuse detected: {count} repeated PERMISSION_DENIED responses "
                f"for '{entity_id}' within {win_sec}s (threshold >= {thresh})."
            ),
            created_at=event_ts,
        )

    return None


def check_camera_tampering(
    db: Session,
    *,
    event: SecurityEvent | None = None,
    camera_id: str | None = None,
    timeout_seconds: int | None = None,
    as_of: datetime | None = None,
    cfg: Settings | None = None,
) -> Alert | None:
    """Rule 6: camera heartbeat missing for N minutes or sudden feed stop."""
    app_cfg = cfg or settings
    timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else app_cfg.rule_camera_heartbeat_timeout_seconds
    )

    # 1. Immediate trigger on CAMERA_OFFLINE (sudden feed stop)
    if event is not None:
        if event.event_type == EventType.CAMERA_OFFLINE.value or event.event_type == "CAMERA_OFFLINE":
            cam = event.camera_id or camera_id or "unknown_camera"
            ts = _norm_ts(event.timestamp)
            return Alert(
                rule_id="RULE_CAMERA_TAMPERING",
                severity=Severity.CRITICAL,
                entity_type="camera",
                entity_id=cam,
                evidence={
                    "camera_id": cam,
                    "trigger": "CAMERA_OFFLINE",
                    "timestamp": ts.isoformat(),
                    "metadata": event.event_metadata,
                },
                reason=f"Camera tampering detected: sudden feed stop / offline event for camera '{cam}'.",
                created_at=ts,
            )

    # 2. Heartbeat missing check for a specific camera
    target_cam = camera_id or (event.camera_id if event else None)
    if not target_cam:
        return None

    ref_time = _norm_ts(as_of or (event.timestamp if event else datetime.now(timezone.utc)))

    stmt = (
        select(SecurityEvent.timestamp)
        .where(
            SecurityEvent.camera_id == target_cam,
            SecurityEvent.event_type == EventType.CAMERA_HEARTBEAT.value,
            SecurityEvent.timestamp <= ref_time,
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(1)
    )
    last_hb = db.scalar(stmt)

    if last_hb is None:
        # Camera has never sent a heartbeat prior to ref_time
        return Alert(
            rule_id="RULE_CAMERA_TAMPERING",
            severity=Severity.CRITICAL,
            entity_type="camera",
            entity_id=target_cam,
            evidence={
                "camera_id": target_cam,
                "trigger": "NO_HEARTBEAT_RECORDED",
                "timeout_seconds": timeout,
            },
            reason=f"Camera tampering detected: no heartbeat ever recorded for camera '{target_cam}'.",
            created_at=ref_time,
        )

    last_hb_utc = _norm_ts(last_hb)
    elapsed = (ref_time - last_hb_utc).total_seconds()
    if elapsed > timeout:
        return Alert(
            rule_id="RULE_CAMERA_TAMPERING",
            severity=Severity.CRITICAL,
            entity_type="camera",
            entity_id=target_cam,
            evidence={
                "camera_id": target_cam,
                "trigger": "HEARTBEAT_MISSING",
                "last_heartbeat": last_hb_utc.isoformat(),
                "elapsed_seconds": int(elapsed),
                "timeout_seconds": timeout,
            },
            reason=(
                f"Camera tampering detected: camera '{target_cam}' heartbeat missing for "
                f"{int(elapsed)}s (timeout {timeout}s)."
            ),
            created_at=ref_time,
        )

    return None


def check_all_cameras_heartbeat(
    db: Session,
    *,
    timeout_seconds: int | None = None,
    as_of: datetime | None = None,
    cfg: Settings | None = None,
) -> list[Alert]:
    """Scan all cameras registered in the event log and detect missing heartbeats."""
    stmt = select(SecurityEvent.camera_id).where(SecurityEvent.camera_id.is_not(None)).distinct()
    camera_ids = [c for c in db.scalars(stmt) if c]

    alerts: list[Alert] = []
    for cam in camera_ids:
        alert = check_camera_tampering(
            db,
            camera_id=cam,
            timeout_seconds=timeout_seconds,
            as_of=as_of,
            cfg=cfg,
        )
        if alert:
            alerts.append(alert)
    return alerts


def evaluate_rules(
    db: Session,
    event: SecurityEvent,
    *,
    cfg: Settings | None = None,
) -> list[Alert]:
    """Evaluate all independent rules against a newly ingested security event."""
    alerts: list[Alert] = []

    # Rule 1: Brute Force
    if alert := check_brute_force(db, event, cfg=cfg):
        alerts.append(alert)

    # Rule 2: Credential Stuffing
    if alert := check_credential_stuffing(db, event, cfg=cfg):
        alerts.append(alert)

    # Rule 3: Impossible Access
    if alert := check_impossible_access(db, event, cfg=cfg):
        alerts.append(alert)

    # Rule 4: Mass Export
    if alert := check_mass_export(db, event, cfg=cfg):
        alerts.append(alert)

    # Rule 5: Privilege Abuse
    if alert := check_privilege_abuse(db, event, cfg=cfg):
        alerts.append(alert)

    # Rule 6: Camera Tampering (event-based check)
    if alert := check_camera_tampering(db, event=event, cfg=cfg):
        alerts.append(alert)

    return alerts
