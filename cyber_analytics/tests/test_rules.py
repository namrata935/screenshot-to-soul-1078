"""Unit tests for Rule-Based Detection Engine (Phase 2)."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.detection.alerts_store import AlertStore
from app.detection.rules import (
    Alert,
    Severity,
    check_all_cameras_heartbeat,
    check_brute_force,
    check_camera_tampering,
    check_credential_stuffing,
    check_impossible_access,
    check_mass_export,
    check_privilege_abuse,
    evaluate_rules,
)
from app.events import log_security_event
from app.models import Base, EventType, SecurityEvent


@pytest.fixture()
def db_session() -> Session:
    """In-memory SQLite database session for fast, isolated rule unit tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def _make_event(
    db: Session,
    *,
    event_type: str,
    ip_address: str = "192.168.1.100",
    user_id: str | None = None,
    username_attempted: str | None = None,
    camera_id: str | None = None,
    video_id: str | None = None,
    success: bool = True,
    timestamp: datetime | None = None,
) -> SecurityEvent:
    row = SecurityEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        event_type=event_type,
        ip_address=ip_address,
        user_id=user_id,
        username_attempted=username_attempted,
        user_agent="pytest-runner/1.0",
        device_fingerprint="fp-" + ip_address,
        camera_id=camera_id,
        video_id=video_id,
        success=success,
        event_metadata={},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ---------------------------------------------------------------------------
# Rule 1: Brute Force Tests
# ---------------------------------------------------------------------------

def test_brute_force_single_ip_triggers_above_threshold(db_session: Session):
    now = datetime.now(timezone.utc)
    # Add 5 failed logins within 60s (threshold is >5)
    for i in range(5):
        _make_event(
            db_session,
            event_type=EventType.LOGIN_FAILED.value,
            ip_address="hash-ip-1",
            username_attempted="admin",
            success=False,
            timestamp=now - timedelta(seconds=50 - (i * 5)),
        )
    # 5th failed event: should NOT trigger (threshold > 5)
    fifth_event = _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="hash-ip-1",
        username_attempted="admin",
        success=False,
        timestamp=now - timedelta(seconds=10),
    )
    alert = check_brute_force(db_session, fifth_event, window_seconds=60, threshold=5)
    # 5 total before was 5, now 6 total in DB
    assert alert is not None
    assert alert.rule_id == "RULE_BRUTE_FORCE"
    assert alert.severity == Severity.HIGH
    assert alert.entity_type == "ip"
    assert alert.entity_id == "hash-ip-1"
    assert alert.evidence["failed_count"] == 6


def test_brute_force_below_threshold_does_not_trigger(db_session: Session):
    now = datetime.now(timezone.utc)
    # Only 3 failed attempts
    for i in range(2):
        _make_event(
            db_session,
            event_type=EventType.LOGIN_FAILED.value,
            ip_address="hash-ip-2",
            username_attempted="alice",
            success=False,
            timestamp=now - timedelta(seconds=30 - (i * 5)),
        )
    third = _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="hash-ip-2",
        username_attempted="alice",
        success=False,
        timestamp=now,
    )
    alert = check_brute_force(db_session, third, window_seconds=60, threshold=5)
    assert alert is None


def test_brute_force_distributed_against_single_account(db_session: Session):
    """Multiple different IPs attacking the same account."""
    now = datetime.now(timezone.utc)
    for i in range(5):
        _make_event(
            db_session,
            event_type=EventType.LOGIN_FAILED.value,
            ip_address=f"hash-ip-{i}",
            username_attempted="target_ceo",
            success=False,
            timestamp=now - timedelta(seconds=50 - (i * 8)),
        )
    sixth = _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="hash-ip-final",
        username_attempted="target_ceo",
        success=False,
        timestamp=now,
    )
    alert = check_brute_force(db_session, sixth, window_seconds=60, threshold=5)
    assert alert is not None
    assert alert.entity_type == "user"
    assert alert.entity_id == "target_ceo"
    assert alert.evidence["failed_count"] == 6


# ---------------------------------------------------------------------------
# Rule 2: Credential Stuffing Tests
# ---------------------------------------------------------------------------

def test_credential_stuffing_triggers_on_3_distinct_usernames(db_session: Session):
    now = datetime.now(timezone.utc)
    _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="stuffing-ip",
        username_attempted="user1@org.com",
        success=False,
        timestamp=now - timedelta(seconds=40),
    )
    _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="stuffing-ip",
        username_attempted="user2@org.com",
        success=False,
        timestamp=now - timedelta(seconds=20),
    )
    third = _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="stuffing-ip",
        username_attempted="user3@org.com",
        success=False,
        timestamp=now,
    )
    alert = check_credential_stuffing(db_session, third, window_seconds=120, threshold_usernames=3)
    assert alert is not None
    assert alert.rule_id == "RULE_CREDENTIAL_STUFFING"
    assert alert.severity == Severity.HIGH
    assert alert.entity_id == "stuffing-ip"
    assert alert.evidence["unique_usernames_count"] == 3
    assert set(alert.evidence["distinct_usernames"]) == {"user1@org.com", "user2@org.com", "user3@org.com"}


def test_credential_stuffing_same_username_repeated_does_not_trigger(db_session: Session):
    now = datetime.now(timezone.utc)
    for _ in range(5):
        _make_event(
            db_session,
            event_type=EventType.LOGIN_FAILED.value,
            ip_address="ip-repeated",
            username_attempted="same_user",
            success=False,
            timestamp=now - timedelta(seconds=10),
        )
    event = _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="ip-repeated",
        username_attempted="same_user",
        success=False,
        timestamp=now,
    )
    alert = check_credential_stuffing(db_session, event, threshold_usernames=3)
    assert alert is None


# ---------------------------------------------------------------------------
# Rule 3: Impossible Access Tests
# ---------------------------------------------------------------------------

def test_impossible_access_detected_within_window(db_session: Session):
    now = datetime.now(timezone.utc)
    # Login from IP_A at now - 60s
    _make_event(
        db_session,
        event_type=EventType.LOGIN_SUCCESS.value,
        user_id="operator_bob",
        ip_address="ip-tokyo",
        success=True,
        timestamp=now - timedelta(seconds=60),
    )
    # Login from IP_B at now
    event2 = _make_event(
        db_session,
        event_type=EventType.LOGIN_SUCCESS.value,
        user_id="operator_bob",
        ip_address="ip-london",
        success=True,
        timestamp=now,
    )
    alert = check_impossible_access(db_session, event2, window_seconds=300)
    assert alert is not None
    assert alert.rule_id == "RULE_IMPOSSIBLE_ACCESS"
    assert alert.severity == Severity.CRITICAL
    assert alert.entity_type == "user"
    assert alert.entity_id == "operator_bob"
    assert set(alert.evidence["distinct_ips"]) == {"ip-tokyo", "ip-london"}


def test_impossible_access_same_ip_does_not_trigger(db_session: Session):
    now = datetime.now(timezone.utc)
    _make_event(
        db_session,
        event_type=EventType.LOGIN_SUCCESS.value,
        user_id="operator_bob",
        ip_address="ip-same",
        success=True,
        timestamp=now - timedelta(seconds=30),
    )
    event2 = _make_event(
        db_session,
        event_type=EventType.VIDEO_VIEW.value,
        user_id="operator_bob",
        ip_address="ip-same",
        video_id="vid-1",
        success=True,
        timestamp=now,
    )
    alert = check_impossible_access(db_session, event2, window_seconds=300)
    assert alert is None


def test_impossible_access_outside_window_does_not_trigger(db_session: Session):
    now = datetime.now(timezone.utc)
    # Event 1 hour ago
    _make_event(
        db_session,
        event_type=EventType.LOGIN_SUCCESS.value,
        user_id="operator_bob",
        ip_address="ip-old",
        success=True,
        timestamp=now - timedelta(minutes=60),
    )
    event2 = _make_event(
        db_session,
        event_type=EventType.LOGIN_SUCCESS.value,
        user_id="operator_bob",
        ip_address="ip-new",
        success=True,
        timestamp=now,
    )
    # 5 minute window
    alert = check_impossible_access(db_session, event2, window_seconds=300)
    assert alert is None


# ---------------------------------------------------------------------------
# Rule 4: Mass Export Tests
# ---------------------------------------------------------------------------

def test_mass_export_triggers_above_threshold(db_session: Session):
    now = datetime.now(timezone.utc)
    # Create 10 video view/download events in past 5 minutes
    for i in range(10):
        _make_event(
            db_session,
            event_type=EventType.VIDEO_VIEW.value,
            user_id="suspicious_auditor",
            video_id=f"vid-{i}",
            success=True,
            timestamp=now - timedelta(minutes=5, seconds=i * 10),
        )
    # 11th download event: triggers (threshold is >10)
    event_11 = _make_event(
        db_session,
        event_type=EventType.VIDEO_DOWNLOAD.value,
        user_id="suspicious_auditor",
        video_id="vid-secret",
        success=True,
        timestamp=now,
    )
    alert = check_mass_export(db_session, event_11, window_seconds=600, threshold=10)
    assert alert is not None
    assert alert.rule_id == "RULE_MASS_EXPORT"
    assert alert.severity == Severity.HIGH
    assert alert.entity_id == "suspicious_auditor"
    assert alert.evidence["video_access_count"] == 11


def test_mass_export_normal_activity_does_not_trigger(db_session: Session):
    now = datetime.now(timezone.utc)
    for i in range(4):
        _make_event(
            db_session,
            event_type=EventType.VIDEO_VIEW.value,
            user_id="normal_user",
            video_id=f"vid-{i}",
            success=True,
            timestamp=now - timedelta(minutes=i),
        )
    event = _make_event(
        db_session,
        event_type=EventType.VIDEO_VIEW.value,
        user_id="normal_user",
        video_id="vid-5",
        success=True,
        timestamp=now,
    )
    alert = check_mass_export(db_session, event, window_seconds=600, threshold=10)
    assert alert is None


# ---------------------------------------------------------------------------
# Rule 5: Privilege Abuse Tests
# ---------------------------------------------------------------------------

def test_privilege_abuse_triggers_on_3_permission_denied(db_session: Session):
    now = datetime.now(timezone.utc)
    for i in range(2):
        _make_event(
            db_session,
            event_type=EventType.PERMISSION_DENIED.value,
            user_id="intern_charlie",
            ip_address="10.0.0.5",
            success=False,
            timestamp=now - timedelta(seconds=60 - (i * 20)),
        )
    third = _make_event(
        db_session,
        event_type=EventType.PERMISSION_DENIED.value,
        user_id="intern_charlie",
        ip_address="10.0.0.5",
        success=False,
        timestamp=now,
    )
    alert = check_privilege_abuse(db_session, third, window_seconds=300, threshold=3)
    assert alert is not None
    assert alert.rule_id == "RULE_PRIVILEGE_ABUSE"
    assert alert.severity == Severity.MEDIUM
    assert alert.entity_id == "intern_charlie"
    assert alert.evidence["denied_count"] == 3


def test_privilege_abuse_without_user_id_tracks_by_ip(db_session: Session):
    now = datetime.now(timezone.utc)
    for i in range(2):
        _make_event(
            db_session,
            event_type=EventType.PERMISSION_DENIED.value,
            ip_address="unauth-ip",
            success=False,
            timestamp=now - timedelta(seconds=40 - (i * 15)),
        )
    third = _make_event(
        db_session,
        event_type=EventType.PERMISSION_DENIED.value,
        ip_address="unauth-ip",
        success=False,
        timestamp=now,
    )
    alert = check_privilege_abuse(db_session, third, threshold=3)
    assert alert is not None
    assert alert.entity_type == "ip"
    assert alert.entity_id == "unauth-ip"


# ---------------------------------------------------------------------------
# Rule 6: Camera Tampering Tests
# ---------------------------------------------------------------------------

def test_camera_tampering_sudden_feed_stop_event(db_session: Session):
    event = _make_event(
        db_session,
        event_type=EventType.CAMERA_OFFLINE.value,
        camera_id="CAM-014-VAULT",
        success=False,
    )
    alert = check_camera_tampering(db_session, event=event)
    assert alert is not None
    assert alert.rule_id == "RULE_CAMERA_TAMPERING"
    assert alert.severity == Severity.CRITICAL
    assert alert.entity_id == "CAM-014-VAULT"
    assert alert.evidence["trigger"] == "CAMERA_OFFLINE"


def test_camera_tampering_heartbeat_timeout(db_session: Session):
    now = datetime.now(timezone.utc)
    # Heartbeat was 5 minutes ago (300s > 180s timeout)
    _make_event(
        db_session,
        event_type=EventType.CAMERA_HEARTBEAT.value,
        camera_id="CAM-002-PERIMETER",
        timestamp=now - timedelta(seconds=300),
    )
    alert = check_camera_tampering(
        db_session,
        camera_id="CAM-002-PERIMETER",
        timeout_seconds=180,
        as_of=now,
    )
    assert alert is not None
    assert alert.rule_id == "RULE_CAMERA_TAMPERING"
    assert alert.entity_id == "CAM-002-PERIMETER"
    assert alert.evidence["trigger"] == "HEARTBEAT_MISSING"
    assert alert.evidence["elapsed_seconds"] >= 300


def test_camera_tampering_fresh_heartbeat_is_healthy(db_session: Session):
    now = datetime.now(timezone.utc)
    _make_event(
        db_session,
        event_type=EventType.CAMERA_HEARTBEAT.value,
        camera_id="CAM-002-PERIMETER",
        timestamp=now - timedelta(seconds=45),
    )
    alert = check_camera_tampering(
        db_session,
        camera_id="CAM-002-PERIMETER",
        timeout_seconds=180,
        as_of=now,
    )
    assert alert is None


def test_check_all_cameras_heartbeat_scans_correctly(db_session: Session):
    now = datetime.now(timezone.utc)
    # Cam A is fresh (40s ago)
    _make_event(
        db_session,
        event_type=EventType.CAMERA_HEARTBEAT.value,
        camera_id="CAM-A",
        timestamp=now - timedelta(seconds=40),
    )
    # Cam B is stale (250s ago > 180s)
    _make_event(
        db_session,
        event_type=EventType.CAMERA_HEARTBEAT.value,
        camera_id="CAM-B",
        timestamp=now - timedelta(seconds=250),
    )
    stale_alerts = check_all_cameras_heartbeat(db_session, timeout_seconds=180, as_of=now)
    assert len(stale_alerts) == 1
    assert stale_alerts[0].entity_id == "CAM-B"


# ---------------------------------------------------------------------------
# Pipeline & Configurable Settings Tests
# ---------------------------------------------------------------------------

def test_custom_settings_override_thresholds(db_session: Session):
    custom_cfg = Settings(
        rule_brute_force_threshold=2,  # lowered from 5 to 2
        rule_brute_force_window_seconds=30,
    )
    now = datetime.now(timezone.utc)
    for i in range(2):
        _make_event(
            db_session,
            event_type=EventType.LOGIN_FAILED.value,
            ip_address="attacker-ip",
            timestamp=now - timedelta(seconds=10),
        )
    third = _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="attacker-ip",
        timestamp=now,
    )
    # With custom_cfg, threshold > 2 triggers on 3rd attempt
    alert = check_brute_force(db_session, third, cfg=custom_cfg)
    assert alert is not None
    assert alert.evidence["threshold"] == 2


def test_evaluate_rules_dispatcher_multiple_rules(db_session: Session):
    now = datetime.now(timezone.utc)
    # Set up scenario that triggers both Brute Force AND Credential Stuffing
    for i, user in enumerate(["user1", "user2", "user3", "user4", "user5"]):
        _make_event(
            db_session,
            event_type=EventType.LOGIN_FAILED.value,
            ip_address="multi-threat-ip",
            username_attempted=user,
            success=False,
            timestamp=now - timedelta(seconds=40 - (i * 5)),
        )
    sixth = _make_event(
        db_session,
        event_type=EventType.LOGIN_FAILED.value,
        ip_address="multi-threat-ip",
        username_attempted="user6",
        success=False,
        timestamp=now,
    )
    alerts = evaluate_rules(db_session, sixth)
    rule_ids = {a.rule_id for a in alerts}
    assert "RULE_BRUTE_FORCE" in rule_ids
    assert "RULE_CREDENTIAL_STUFFING" in rule_ids


def test_log_security_event_integration_populates_alert_store(db_session: Session):
    store = AlertStore()
    now = datetime.now(timezone.utc)
    # Create offline camera event
    event = log_security_event(
        db_session,
        event_type=EventType.CAMERA_OFFLINE,
        ip_address="10.0.1.5",
        camera_id="CAM-OFFLINE-TEST",
        success=False,
        run_detection=True,
    )
    triggered = getattr(event, "_triggered_alerts", [])
    assert len(triggered) == 1
    assert triggered[0].rule_id == "RULE_CAMERA_TAMPERING"
    assert triggered[0].entity_id == "CAM-OFFLINE-TEST"
