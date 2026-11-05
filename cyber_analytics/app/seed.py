"""Initial seed data for development and demonstration."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AlertSeverity, AlertStatus, CyberAlert, EventType, SecurityEvent
from app.privacy import hmac_hex, device_fingerprint
from app.config import settings

logger = logging.getLogger(__name__)


def seed_database_if_empty(db: Session) -> None:
    """Populate security events and cyber alerts if database is currently empty."""
    alert_count = db.scalar(select(func.count(CyberAlert.id))) or 0
    if alert_count > 0:
        return

    logger.info("Database is empty. Seeding initial security events and cyber alerts...")
    now = datetime.now(timezone.utc)

    # 1. Normal security events for Identity Graph
    normal_events = [
        SecurityEvent(
            timestamp=now - timedelta(hours=3),
            event_type=EventType.LOGIN_SUCCESS.value,
            user_id="j.mehta",
            username_attempted="j.mehta",
            ip_address="10.0.1.15",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            device_fingerprint="fp_ws01",
            camera_id="CAM-014",
            success=True,
            event_metadata={"role": "lead_operator"},
        ),
        SecurityEvent(
            timestamp=now - timedelta(hours=2, minutes=30),
            event_type=EventType.VIDEO_VIEW.value,
            user_id="j.mehta",
            ip_address="10.0.1.15",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            device_fingerprint="fp_ws01",
            camera_id="CAM-014",
            video_id="vid-101",
            success=True,
        ),
        SecurityEvent(
            timestamp=now - timedelta(hours=2),
            event_type=EventType.LOGIN_SUCCESS.value,
            user_id="usr_alice",
            username_attempted="usr_alice",
            ip_address="10.0.1.15",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1",
            device_fingerprint="fp_ws02",
            camera_id="CAM-014",
            success=True,
        ),
        SecurityEvent(
            timestamp=now - timedelta(hours=1, minutes=45),
            event_type=EventType.VIDEO_VIEW.value,
            user_id="usr_bob",
            ip_address="10.0.4.22",
            user_agent="Mozilla/5.0 (Linux; Android 14) Chrome/120.0",
            device_fingerprint="fp_tablet04",
            camera_id="CAM-011",
            video_id="vid-202",
            success=True,
        ),
        SecurityEvent(
            timestamp=now - timedelta(hours=1),
            event_type=EventType.LOGIN_SUCCESS.value,
            user_id="admin",
            username_attempted="admin",
            ip_address="10.0.1.15",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            device_fingerprint="fp_ws01",
            camera_id="CAM-011",
            success=True,
        ),
        SecurityEvent(
            timestamp=now - timedelta(minutes=40),
            event_type=EventType.CAMERA_HEARTBEAT.value,
            ip_address="10.0.1.200",
            device_fingerprint="fp_cam_014",
            camera_id="CAM-014",
            success=True,
        ),
        SecurityEvent(
            timestamp=now - timedelta(minutes=35),
            event_type=EventType.CAMERA_HEARTBEAT.value,
            ip_address="10.0.1.201",
            device_fingerprint="fp_cam_002",
            camera_id="CAM-002",
            success=True,
        ),
    ]

    for ev in normal_events:
        db.add(ev)

    # 2. Seed Real Cyber Alerts
    alerts = [
        CyberAlert(
            rule_id="RULE_CAMERA_TAMPERING",
            severity=AlertSeverity.CRITICAL.value,
            status=AlertStatus.OPEN.value,
            entity_type="camera",
            entity_id="CAM-007",
            user_id=None,
            ip_address="185.220.101.4",
            camera_id="CAM-007",
            confidence=0.98,
            explanation="Camera tampering detected: camera 'CAM-007' heartbeat missing for 240s (timeout 180s) followed by unauthorized RTSP handshake attempt.",
            raw_evidence={
                "trigger": "HEARTBEAT_MISSING",
                "timeout_seconds": 180,
                "elapsed_seconds": 240,
                "suspected_ip": "185.220.101.4",
            },
            created_at=now - timedelta(minutes=4),
        ),
        CyberAlert(
            rule_id="RULE_BRUTE_FORCE",
            severity=AlertSeverity.HIGH.value,
            status=AlertStatus.OPEN.value,
            entity_type="ip",
            entity_id="45.155.205.9",
            user_id="admin",
            ip_address="45.155.205.9",
            camera_id=None,
            confidence=0.94,
            explanation="Brute force authentication attack: 14 failed logins observed from IP 45.155.205.9 against user 'admin' in 45s.",
            raw_evidence={
                "failed_count": 14,
                "target_user": "admin",
                "window_seconds": 60,
                "user_agent": "masscan/1.3 (Security Scanner)",
            },
            created_at=now - timedelta(minutes=12),
        ),
        CyberAlert(
            rule_id="ML_ANOMALY",
            severity=AlertSeverity.HIGH.value,
            status=AlertStatus.ACKNOWLEDGED.value,
            entity_type="user",
            entity_id="usr_alice",
            user_id="usr_alice",
            ip_address="203.0.113.88",
            camera_id="CAM-014",
            confidence=0.89,
            explanation="ML Behavioral Anomaly (IsolationForest score 0.89): Sudden access from foreign subnet and unverified device fingerprint.",
            raw_evidence={
                "ml_score": 0.892,
                "top_reasons": [
                    "Unrecognized device fingerprint (fp_unknown_darwin_arm)",
                    "New IP subnet 203.0.113.0/24",
                    "Off-hours access at 03:22 UTC",
                ],
                "user_baseline_deviation": "High",
            },
            created_at=now - timedelta(minutes=25),
        ),
        CyberAlert(
            rule_id="RULE_CREDENTIAL_STUFFING",
            severity=AlertSeverity.CRITICAL.value,
            status=AlertStatus.OPEN.value,
            entity_type="ip",
            entity_id="198.51.100.44",
            user_id=None,
            ip_address="198.51.100.44",
            camera_id=None,
            confidence=0.96,
            explanation="Credential stuffing campaign: single IP failing authentication across 6 distinct operator accounts within 90s.",
            raw_evidence={
                "targeted_usernames": ["admin", "j.mehta", "operator2", "s.khan", "supervisor", "root"],
                "attempts": 18,
                "source_asn": "AS208843",
            },
            created_at=now - timedelta(minutes=48),
        ),
        CyberAlert(
            rule_id="RULE_MASS_EXPORT",
            severity=AlertSeverity.MEDIUM.value,
            status=AlertStatus.OPEN.value,
            entity_type="user",
            entity_id="usr_bob",
            user_id="usr_bob",
            ip_address="10.0.4.22",
            camera_id="CAM-011",
            confidence=0.83,
            explanation="Mass video export threshold exceeded: 22 high-resolution video streams requested in under 6 minutes.",
            raw_evidence={
                "video_count": 22,
                "total_bytes_mb": 1840,
                "window_seconds": 360,
            },
            created_at=now - timedelta(minutes=70),
        ),
        CyberAlert(
            rule_id="RULE_PRIVILEGE_ABUSE",
            severity=AlertSeverity.MEDIUM.value,
            status=AlertStatus.RESOLVED.value,
            entity_type="user",
            entity_id="usr_carol",
            user_id="usr_carol",
            ip_address="10.0.1.45",
            camera_id="CAM-019",
            confidence=0.78,
            explanation="Repeated permission denied: 7 attempts to modify camera PTZ presets and encryption parameters without admin authorization.",
            raw_evidence={
                "denial_count": 7,
                "endpoint_attempted": "PATCH /api/v1/cameras/CAM-019/ptz",
            },
            created_at=now - timedelta(minutes=98),
        ),
    ]

    for a in alerts:
        db.add(a)

    db.commit()
    logger.info("Successfully seeded database with security events and cyber alerts.")

