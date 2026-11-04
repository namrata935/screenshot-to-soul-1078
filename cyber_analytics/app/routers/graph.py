"""FastAPI endpoints for Cybersecurity Identity & Camera Graph visualization."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.graph.identity_graph import (
    GraphResponse,
    IdentityGraph,
    build_identity_graph_from_events,
)
from app.models import SecurityEvent

router = APIRouter(prefix="/api/v1/graph", tags=["identity-graph"])


@router.get(
    "/identity",
    response_model=GraphResponse,
    dependencies=[Depends(require_admin)],
)
def get_identity_graph(
    db: Session = Depends(get_db),
    user_id: str | None = Query(default=None, description="Filter subgraph to specified user and their neighbors"),
    camera_id: str | None = Query(default=None, description="Filter subgraph to specified camera and connected entities"),
    days: int = Query(default=7, ge=1, le=90, description="Window of historical events to build graph from"),
    limit: int = Query(default=400, ge=10, le=2000, description="Maximum events to query"),
):
    """Return nodes and edges connecting users, devices, IPs, and cameras.

    Useful for answering forensics questions:
    - Which foreign devices or IPs touched which cameras?
    - What is the operational blast radius of a compromised credential?
    """
    days_val = int(days.default if hasattr(days, "default") else days)
    limit_val = int(limit.default if hasattr(limit, "default") else limit)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days_val)
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.timestamp >= cutoff)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit_val)
    )

    if user_id:
        stmt = stmt.where(
            or_(
                SecurityEvent.user_id == user_id,
                SecurityEvent.username_attempted == user_id,
            )
        )
    elif camera_id:
        stmt = stmt.where(SecurityEvent.camera_id == camera_id)

    events = list(db.scalars(stmt))

    graph = build_identity_graph_from_events(events)

    if user_id:
        return graph.get_user_subgraph(user_id, hops=2)
    if camera_id:
        return graph.get_camera_subgraph(camera_id, hops=2)

    return graph.to_response()
