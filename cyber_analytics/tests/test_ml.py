"""Unit tests for ML Anomaly Detection (Phase 3)."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest

from app.ml.anomaly import MLAnomalyDetector
from app.ml.features import (
    FEATURE_NAMES,
    UserBaseline,
    build_user_baseline,
    extract_features_from_event,
)
from app.models import EventType, SecurityEvent


def _make_event(
    *,
    user_id: str = "u_alice",
    username: str = "alice",
    event_type: str | None = None,
    ip_address: str = "10.0.0.1",
    device_fp: str = "fp_laptop_1",
    timestamp: datetime,
    video_id: str | None = None,
    success: bool = True,
) -> SecurityEvent:
    ev_type = event_type or (EventType.VIDEO_VIEW.value if video_id else EventType.LOGIN_SUCCESS.value)
    return SecurityEvent(
        id=uuid.uuid4(),
        timestamp=timestamp,
        event_type=ev_type,
        user_id=user_id,
        username_attempted=username,
        ip_address=ip_address,
        user_agent="Mozilla/5.0",
        device_fingerprint=device_fp,
        camera_id="CAM-1" if video_id else None,
        video_id=video_id,
        success=success,
        event_metadata={},
    )


def test_feature_extraction_fields_and_rates():
    base_ts = datetime(2026, 11, 2, 14, 30, tzinfo=timezone.utc)  # Monday 14:30
    e1 = _make_event(timestamp=base_ts - timedelta(minutes=40), video_id="vid-1")
    e2 = _make_event(timestamp=base_ts - timedelta(minutes=10), video_id="vid-2")
    e3 = _make_event(timestamp=base_ts, video_id="vid-3")

    history = [e1, e2]
    feats = extract_features_from_event(e3, history=history)

    assert set(feats.keys()) == set(FEATURE_NAMES)
    assert feats["login_hour"] == 14.5
    assert feats["day_of_week"] == 0.0  # Monday
    assert feats["request_rate"] == 3.0  # e1, e2, e3 within 60 min
    assert feats["videos_accessed_per_hour"] == 3.0
    assert feats["is_new_device"] == 0.0  # same device as e1 and e2


def test_user_baseline_building():
    base_ts = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)
    events = [
        _make_event(timestamp=base_ts + timedelta(hours=i), ip_address="10.0.0.1", device_fp="fp_workstation")
        for i in range(8)  # 09:00 to 16:00
    ]

    baseline = build_user_baseline("u_alice", events)

    assert baseline.user_id == "u_alice"
    assert "fp_workstation" in baseline.known_devices
    assert "10.0.0.1" in baseline.known_ips
    assert baseline.min_hour == 9
    assert baseline.max_hour == 16
    assert 12 in baseline.active_hours
    assert baseline.is_hour_unusual(3) is True
    assert baseline.is_hour_unusual(10) is False
    assert baseline.is_device_new("fp_workstation") is False
    assert baseline.is_device_new("fp_unknown_kali") is True
    assert baseline.is_ip_new("192.168.99.99") is True


def test_ml_anomaly_detector_training_and_normal_inference():
    base_ts = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
    train_events = []
    # Build a stable history of normal office hours
    for day in range(5):
        day_ts = base_ts + timedelta(days=day)
        for h in range(9, 17):
            train_events.append(_make_event(
                timestamp=day_ts.replace(hour=h, minute=15),
                ip_address="10.0.0.1",
                device_fp="fp_workstation",
            ))

    detector = MLAnomalyDetector(contamination=0.05, n_estimators=50, score_threshold=0.65)
    detector.fit_from_events(train_events)
    assert detector.is_fitted is True
    assert "u_alice" in detector.baselines

    # Normal office hour event from known workstation on a normal working day (Wednesday 13:00)
    normal_event = _make_event(
        timestamp=base_ts + timedelta(days=2, hours=3),  # 13:00
        ip_address="10.0.0.1",
        device_fp="fp_workstation",
    )
    res = detector.detect(normal_event, history=train_events)
    assert res.is_anomaly is False
    assert res.anomaly_score < 0.65
    alert = detector.as_alert(normal_event, history=train_events)
    assert alert is None


def test_ml_anomaly_detector_catches_off_hours_new_device_compromise():
    base_ts = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
    train_events = [
        _make_event(
            timestamp=base_ts + timedelta(hours=i),
            ip_address="10.0.0.1",
            device_fp="fp_workstation",
        )
        for i in range(10)
    ]

    detector = MLAnomalyDetector(contamination=0.05, n_estimators=50, score_threshold=0.65)
    detector.fit_from_events(train_events)

    # Attack: 03:15 AM login from unknown foreign IP and foreign device
    attack_ts = datetime(2026, 11, 3, 3, 15, tzinfo=timezone.utc)
    attack_event = _make_event(
        timestamp=attack_ts,
        ip_address="198.51.100.99",
        device_fp="fp_rogue_device",
        event_type=EventType.LOGIN_SUCCESS.value,
    )

    res = detector.detect(attack_event, history=train_events)
    assert res.is_anomaly is True
    assert res.anomaly_score >= 0.65
    assert any("Login at 03:15" in r for r in res.reasons)
    assert any("never-seen device" in r for r in res.reasons)
    assert any("never-seen IP" in r for r in res.reasons)

    # Convert to Alert
    alert = detector.as_alert(attack_event, history=train_events)
    assert alert is not None
    assert alert.rule_id == "ML_ANOMALY"
    assert alert.confidence >= 0.65
    assert "never-seen device" in alert.reason


def test_ml_anomaly_detector_catches_video_scraping_spike():
    base_ts = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
    # Baseline with low normal video rate (e.g. 1 video per few hours)
    train_events = [
        _make_event(
            timestamp=base_ts + timedelta(hours=i),
            ip_address="10.0.0.1",
            device_fp="fp_workstation",
            video_id=f"vid-{i}" if i % 3 == 0 else None,
        )
        for i in range(12)
    ]

    detector = MLAnomalyDetector(contamination=0.05, n_estimators=50, score_threshold=0.65)
    detector.fit_from_events(train_events)

    # Spike: rapid 12 video downloads in 5 minutes
    spike_history = list(train_events)
    spike_base = base_ts + timedelta(days=1)
    last_event = None
    for j in range(12):
        ev = _make_event(
            timestamp=spike_base + timedelta(seconds=j * 20),
            ip_address="10.0.0.1",
            device_fp="fp_workstation",
            event_type=EventType.VIDEO_DOWNLOAD.value,
            video_id=f"secret-vid-{j}",
        )
        spike_history.append(ev)
        last_event = ev

    res = detector.detect(last_event, history=spike_history[:-1])
    assert res.is_anomaly is True
    assert res.anomaly_score >= 0.65
    assert any("video access" in r.lower() or "spike" in r.lower() for r in res.reasons)
