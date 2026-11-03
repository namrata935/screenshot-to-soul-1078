from fastapi.testclient import TestClient

from app.config import settings
from app.privacy import device_fingerprint, hmac_hex


def _admin_headers() -> dict[str, str]:
    return {"X-Admin-Key": settings.cyber_admin_api_key}


def test_login_success_is_logged_without_password(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "j.mehta", "password": "correct"},
        headers={"User-Agent": "pytest-agent"},
    )
    assert response.status_code == 200

    events = client.get("/api/v1/security-events", headers=_admin_headers()).json()
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "LOGIN_SUCCESS"
    assert event["success"] is True
    assert event["username_attempted"] == "j.mehta"
    assert event["device_fingerprint"] == device_fingerprint("pytest-agent", "testclient")
    assert event["ip_address"] == hmac_hex("testclient", settings.cyber_hmac_secret)
    assert event["ip_address"] != "testclient"
    assert "password" not in (event.get("metadata") or {})
    dumped = str(event)
    assert "correct" not in dumped


def test_login_failure_is_logged(client: TestClient):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401
    events = client.get("/api/v1/security-events", headers=_admin_headers()).json()
    assert events[0]["event_type"] == "LOGIN_FAILED"
    assert events[0]["success"] is False


def test_video_view_and_permission_denied(client: TestClient):
    ok = client.get("/api/v1/videos/vid-1")
    denied = client.get("/api/v1/videos/vid-1", headers={"X-Role": "denied"})
    assert ok.status_code == 200
    assert denied.status_code == 403

    events = client.get("/api/v1/security-events", headers=_admin_headers()).json()
    types = [e["event_type"] for e in events]
    assert "PERMISSION_DENIED" in types
    assert "VIDEO_VIEW" in types
    view = next(e for e in events if e["event_type"] == "VIDEO_VIEW")
    assert view["video_id"] == "vid-1"


def test_camera_heartbeat_and_role_change(client: TestClient):
    hb = client.post("/api/v1/cameras/CAM-014/heartbeat")
    role = client.patch("/api/v1/users/u-9/role", json={"role": "admin"})
    assert hb.status_code == 200
    assert role.status_code == 200
    events = client.get("/api/v1/security-events", headers=_admin_headers()).json()
    types = {e["event_type"] for e in events}
    assert {"CAMERA_HEARTBEAT", "ROLE_CHANGE"} <= types
    heartbeat = next(e for e in events if e["event_type"] == "CAMERA_HEARTBEAT")
    assert heartbeat["camera_id"] == "CAM-014"


def test_ingest_endpoint_accepts_external_events(client: TestClient):
    response = client.post(
        "/api/v1/security-events",
        json={
            "event_type": "VIDEO_DOWNLOAD",
            "user_id": "j.mehta",
            "ip_address": "10.0.1.12",
            "user_agent": "VMS/1.0",
            "video_id": "vid-88",
            "success": True,
            "metadata": {"password": "should-not-store", "bytes": 12},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["event_type"] == "VIDEO_DOWNLOAD"
    assert body["video_id"] == "vid-88"
    assert body["metadata"]["bytes"] == 12
    assert "password" not in body["metadata"]


def test_list_events_requires_admin_key(client: TestClient):
    denied = client.get("/api/v1/security-events")
    assert denied.status_code == 403
