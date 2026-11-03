from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.events import log_security_event
from app.middleware import client_ip
from app.models import SecurityEvent
from app.schemas import SecurityEventIn, SecurityEventOut
from fastapi import Request

router = APIRouter(prefix="/api/v1", tags=["security-events"])


@router.post("/security-events", response_model=SecurityEventOut)
def ingest_event(
    payload: SecurityEventIn,
    request: Request,
    db: Session = Depends(get_db),
):
    """Accept a security event from another VMS service (model server, future auth API)."""
    row = log_security_event(
        db,
        event_type=payload.event_type,
        ip_address=payload.ip_address or client_ip(request),
        user_agent=payload.user_agent or request.headers.get("user-agent"),
        user_id=payload.user_id,
        username_attempted=payload.username_attempted,
        camera_id=payload.camera_id,
        video_id=payload.video_id,
        success=payload.success,
        metadata=payload.metadata,
    )
    return SecurityEventOut.from_row(row)


@router.get("/security-events", response_model=list[SecurityEventOut], dependencies=[Depends(require_admin)])
def list_events(
    db: Session = Depends(get_db),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
):
    stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    return [SecurityEventOut.from_row(row) for row in db.scalars(stmt)]
