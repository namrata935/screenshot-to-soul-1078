from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.events import log_security_event
from app.middleware import client_ip
from app.models import EventType


def require_admin(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")) -> None:
    """Placeholder admin gate until the frontend grows real auth."""
    if x_admin_key != settings.cyber_admin_api_key:
        raise HTTPException(status_code=403, detail="Admin key required")


def event_logger(request: Request, db: Session = Depends(get_db)):
    """Dependency endpoints can call to record an event explicitly."""

    def _log(
        event_type: EventType | str,
        *,
        success: bool = True,
        user_id: str | None = None,
        username_attempted: str | None = None,
        camera_id: str | None = None,
        video_id: str | None = None,
        metadata: dict | None = None,
    ):
        return log_security_event(
            db,
            event_type=event_type,
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            user_id=user_id,
            username_attempted=username_attempted,
            camera_id=camera_id,
            video_id=video_id,
            success=success,
            metadata=metadata,
        )

    return _log
