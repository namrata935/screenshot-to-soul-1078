"""Automatic security-event logging for auth/video/camera routes."""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.database import SessionLocal
from app.events import log_security_event
from app.models import EventType

_SENSITIVE_BODY_KEYS = frozenset({"password", "passwd", "token", "access_token", "refresh_token", "api_key"})

# Path patterns for the VMS integration hooks and ingest-adjacent routes.
_ROUTE_RULES: list[tuple[re.Pattern[str], str, Callable[[int], EventType | None]]] = [
    (
        re.compile(r"^/api/v1/auth/login/?$"),
        "POST",
        lambda status: EventType.LOGIN_SUCCESS if 200 <= status < 300 else EventType.LOGIN_FAILED,
    ),
    (re.compile(r"^/api/v1/auth/logout/?$"), "POST", lambda _s: EventType.LOGOUT),
    (
        re.compile(r"^/api/v1/videos/([^/]+)/download/?$"),
        "GET",
        lambda status: EventType.VIDEO_DOWNLOAD if status < 400 else None,
    ),
    (
        re.compile(r"^/api/v1/videos/([^/]+)/?$"),
        "GET",
        lambda status: EventType.VIDEO_VIEW if status < 400 else None,
    ),
    (
        re.compile(r"^/api/v1/videos/?$"),
        "POST",
        lambda status: EventType.VIDEO_UPLOAD if status < 400 else None,
    ),
    (
        re.compile(r"^/api/v1/videos/([^/]+)/?$"),
        "DELETE",
        lambda status: EventType.VIDEO_DELETE if status < 400 else None,
    ),
    (
        re.compile(r"^/api/v1/cameras/([^/]+)/heartbeat/?$"),
        "POST",
        lambda status: EventType.CAMERA_HEARTBEAT if status < 400 else None,
    ),
    (
        re.compile(r"^/api/v1/users/([^/]+)/role/?$"),
        "PATCH",
        lambda status: EventType.ROLE_CHANGE if status < 400 else None,
    ),
]


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _safe_json(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


class SecurityEventMiddleware(BaseHTTPMiddleware):
    """Logs platform (not video-content) events after each matching response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        body = await request.body()

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        request = Request(request.scope, receive)
        response = await call_next(request)

        event_type = _classify(request, response.status_code)
        if event_type is None:
            return response

        payload = _safe_json(body)
        video_id = _path_group(request.url.path, r"^/api/v1/videos/([^/]+)")
        camera_id = payload.get("camera_id") or _path_group(
            request.url.path, r"^/api/v1/cameras/([^/]+)"
        )
        user_id = (
            request.headers.get("x-user-id")
            or payload.get("user_id")
            or (_path_group(request.url.path, r"^/api/v1/users/([^/]+)") if event_type == EventType.ROLE_CHANGE else None)
        )
        username = payload.get("username") or request.headers.get("x-username")
        success = 200 <= response.status_code < 300
        meta = {k: v for k, v in payload.items() if k.lower() not in _SENSITIVE_BODY_KEYS}
        if event_type == EventType.ROLE_CHANGE:
            meta["new_role"] = payload.get("role")

        db = SessionLocal()
        try:
            log_security_event(
                db,
                event_type=event_type,
                ip_address=client_ip(request),
                user_agent=request.headers.get("user-agent"),
                user_id=str(user_id) if user_id else None,
                username_attempted=str(username) if username else None,
                camera_id=str(camera_id) if camera_id else None,
                video_id=video_id,
                success=success,
                metadata=meta,
            )
        finally:
            db.close()
        return response


def _classify(request: Request, status_code: int) -> EventType | None:
    if status_code == 403:
        return EventType.PERMISSION_DENIED
    path = request.url.path
    method = request.method.upper()
    for pattern, want_method, mapper in _ROUTE_RULES:
        if method == want_method and pattern.match(path):
            return mapper(status_code)
    return None


def _path_group(path: str, pattern: str) -> str | None:
    match = re.match(pattern, path)
    return match.group(1) if match else None
