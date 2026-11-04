"""Unit tests for Phase 5: Alerts API, Persistence, and Threat Signal Correlation."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.events import log_security_event, persist_alert
from app.detection.rules import Alert, Severity
from app.models import AlertSeverity, AlertStatus, Base, CyberAlert, EventType, SecurityEvent
from app.routers.alerts import (
    get_alert,
    get_alert_summary,
    get_cyber_signals,
    list_alerts,
    update_alert_status,
)
from app.schemas import CyberAlertStatusUpdate


@pytest.fixture()
def db_session() -> Session:
    """In-memory SQLite session for alerts unit tests."""
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


def _create_test_alert(
    db: Session,
    *,
    rule_id: str = "RULE_BRUTE_FORCE",
    severity: str = "critical",
    status: str = "open",
    entity_type: str = "user",
    entity_id: str = "usr_alice",
    user_id: str | None = "usr_alice",
    camera_id: str | None = None,
    ip_address: str | None = "192.168.1.50",
    confidence: float = 1.0,
    created_at: datetime | None = None,
) -> CyberAlert:
    row = CyberAlert(
        id=uuid.uuid4(),
        rule_id=rule_id,
        severity=severity,
        status=status,
        entity_type=entity_type,
        entity_id=entity_id,
        user_id=user_id,
        camera_id=camera_id,
        ip_address=ip_address,
        confidence=confidence,
        explanation=f"Alert triggered by {rule_id}",
        raw_evidence={"count": 6},
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_persist_alert_creates_database_record(db_session: Session):
    in_memory = Alert(
        rule_id="RULE_IMPOSSIBLE_ACCESS",
        severity=Severity.HIGH,
        entity_type="user",
        entity_id="usr_bob",
        evidence={"ip_list": ["10.0.0.1", "10.0.0.2"]},
        reason="Impossible concurrent travel between IPs",
        confidence=0.95,
    )
    db_alert = persist_alert(db_session, in_memory)

    assert db_alert.id is not None
    assert db_alert.rule_id == "RULE_IMPOSSIBLE_ACCESS"
    assert db_alert.severity == "high"
    assert db_alert.status == "open"
    assert db_alert.entity_id == "usr_bob"
    assert db_alert.confidence == 0.95
    assert "Impossible concurrent" in db_alert.explanation


def test_list_and_filter_alerts(db_session: Session):
    _create_test_alert(db_session, rule_id="RULE_BRUTE_FORCE", severity="critical", status="open")
    _create_test_alert(db_session, rule_id="RULE_MASS_EXPORT", severity="high", status="open")
    _create_test_alert(db_session, rule_id="ML_ANOMALY", severity="medium", status="resolved")

    # Filter by status
    open_alerts = list_alerts(db=db_session, status="open")
    assert len(open_alerts) == 2
    assert all(a.status == "open" for a in open_alerts)

    # Filter by severity
    crit_alerts = list_alerts(db=db_session, severity="critical")
    assert len(crit_alerts) == 1
    assert crit_alerts[0].rule_id == "RULE_BRUTE_FORCE"

    # Filter by rule_id
    ml_alerts = list_alerts(db=db_session, rule_id="ML_ANOMALY")
    assert len(ml_alerts) == 1
    assert ml_alerts[0].status == "resolved"


def test_get_alert_and_not_found(db_session: Session):
    alert = _create_test_alert(db_session)
    fetched = get_alert(alert.id, db=db_session)
    assert fetched.id == alert.id
    assert fetched.rule_id == alert.rule_id

    with pytest.raises(Exception):
        get_alert(uuid.uuid4(), db=db_session)


def test_update_alert_status_lifecycle(db_session: Session):
    alert = _create_test_alert(db_session, status="open")

    # Acknowledge
    ack_res = update_alert_status(
        alert.id,
        CyberAlertStatusUpdate(status=AlertStatus.ACKNOWLEDGED),
        db=db_session,
    )
    assert ack_res.status == "acknowledged"

    # Resolve
    res_res = update_alert_status(
        alert.id,
        CyberAlertStatusUpdate(status=AlertStatus.RESOLVED),
        db=db_session,
    )
    assert res_res.status == "resolved"


def test_alert_summary_metrics(db_session: Session):
    _create_test_alert(db_session, severity="critical", status="open", ip_address="192.168.1.100")
    _create_test_alert(db_session, severity="critical", status="open", ip_address="192.168.1.100")
    _create_test_alert(db_session, severity="high", status="acknowledged", ip_address="10.0.0.1")
    _create_test_alert(db_session, severity="low", status="resolved", ip_address="10.0.0.1")

    summary = get_alert_summary(db=db_session, days=7)
    assert summary.total_alerts == 4
    assert summary.open_alerts == 2
    assert summary.acknowledged_alerts == 1
    assert summary.resolved_alerts == 1
    assert summary.by_severity["critical"] == 2
    assert summary.top_suspicious_ips[0]["ip_address"] == "192.168.1.100"
    assert summary.top_suspicious_ips[0]["alert_count"] == 2


def test_cyber_signals_correlation_for_camera(db_session: Session):
    now = datetime.now(timezone.utc)
    # Camera with active tampering / brute force alert
    _create_test_alert(
        db_session,
        rule_id="RULE_CAMERA_TAMPERING",
        severity="critical",
        status="open",
        camera_id="CAM-PERIMETER-01",
        created_at=now - timedelta(minutes=2),
    )

    # Correlate for CAM-PERIMETER-01
    signals = get_cyber_signals(
        db_session,
        camera_id="CAM-PERIMETER-01",
        window_seconds=600,
    )
    assert signals.target_camera == "CAM-PERIMETER-01"
    assert signals.has_active_cyber_threat is True
    assert signals.cyber_threat_score >= 0.60
    assert len(signals.active_alerts) == 1
    assert any("Critical Cyber Alert" in ind for ind in signals.indicators)

    # Camera with clean status
    clean_signals = get_cyber_signals(
        db_session,
        camera_id="CAM-CLEAN-02",
        window_seconds=600,
    )
    assert clean_signals.target_camera == "CAM-CLEAN-02"
    assert clean_signals.has_active_cyber_threat is False
    assert clean_signals.cyber_threat_score == 0.0
    assert len(clean_signals.active_alerts) == 0
