"""Unit tests for Cybersecurity Identity Graph (Phase 4)."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.graph.identity_graph import (
    GraphResponse,
    IdentityGraph,
    build_identity_graph_from_events,
)
from app.models import Base, EventType, SecurityEvent
from app.routers.graph import get_identity_graph


@pytest.fixture()
def db_session() -> Session:
    """In-memory SQLite session for graph router tests."""
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
    *,
    user_id: str = "usr_alice",
    username: str = "alice_soc",
    device_fp: str = "fp_laptop_alice",
    ip_address: str = "10.0.1.50",
    camera_id: str | None = "CAM-001-GATE",
    timestamp: datetime | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        id=uuid.uuid4(),
        timestamp=timestamp or datetime.now(timezone.utc),
        event_type=EventType.VIDEO_VIEW.value,
        user_id=user_id,
        username_attempted=username,
        ip_address=ip_address,
        user_agent="VMS-Client/3.0",
        device_fingerprint=device_fp,
        camera_id=camera_id,
        video_id="vid_101",
        success=True,
        event_metadata={"masked_ip": "10.0.1.xxx"},
    )


def test_identity_graph_build_nodes_and_edges():
    e1 = _make_event(
        user_id="usr_alice",
        username="alice",
        device_fp="fp_alice_laptop",
        ip_address="10.0.1.10",
        camera_id="CAM-01",
    )
    e2 = _make_event(
        user_id="usr_alice",
        username="alice",
        device_fp="fp_alice_laptop",
        ip_address="10.0.1.10",
        camera_id="CAM-01",
    )

    graph = build_identity_graph_from_events([e1, e2])
    res = graph.to_response()

    # 4 distinct nodes: user, device, ip, camera
    node_types = {n.type for n in res.nodes}
    assert node_types == {"user", "device", "ip", "camera"}
    assert res.total_nodes == 4

    user_node = next(n for n in res.nodes if n.type == "user")
    assert user_node.id == "user:usr_alice"
    assert user_node.event_count == 2

    # Edges
    relations = {e.relation for e in res.edges}
    assert "USED_DEVICE" in relations
    assert "USED_IP" in relations
    assert "ACCESSED_CAMERA" in relations

    # Weight should be 2 for the repeated interaction
    user_dev_edge = next(e for e in res.edges if e.relation == "USED_DEVICE")
    assert user_dev_edge.weight == 2


def test_user_subgraph_isolates_blast_radius():
    # Alice on Cam-1
    e_alice = _make_event(
        user_id="usr_alice",
        device_fp="fp_alice",
        ip_address="10.0.1.1",
        camera_id="CAM-01",
    )
    # Bob on Cam-2
    e_bob = _make_event(
        user_id="usr_bob",
        device_fp="fp_bob",
        ip_address="10.0.2.2",
        camera_id="CAM-02",
    )

    graph = build_identity_graph_from_events([e_alice, e_bob])

    # Query Alice subgraph
    alice_sub = graph.get_user_subgraph("usr_alice", hops=2)
    node_ids = {n.id for n in alice_sub.nodes}

    assert "user:usr_alice" in node_ids
    assert "device:fp_alice" in node_ids
    assert "ip:10.0.1.1" in node_ids
    assert "camera:CAM-01" in node_ids

    # Bob's entities must not be in Alice's isolated subgraph
    assert "user:usr_bob" not in node_ids
    assert "device:fp_bob" not in node_ids
    assert "camera:CAM-02" not in node_ids


def test_camera_subgraph_reveals_who_touched_camera():
    e_alice = _make_event(
        user_id="usr_alice",
        device_fp="fp_alice",
        ip_address="10.0.1.1",
        camera_id="CAM-VAULT",
    )
    e_rogue = _make_event(
        user_id="usr_rogue",
        device_fp="fp_foreign_box",
        ip_address="198.51.100.22",
        camera_id="CAM-VAULT",
    )
    e_other = _make_event(
        user_id="usr_charlie",
        device_fp="fp_charlie",
        ip_address="10.0.5.5",
        camera_id="CAM-PARKING",
    )

    graph = build_identity_graph_from_events([e_alice, e_rogue, e_other])

    # Query CAM-VAULT
    cam_sub = graph.get_camera_subgraph("CAM-VAULT", hops=2)
    node_ids = {n.id for n in cam_sub.nodes}

    assert "camera:CAM-VAULT" in node_ids
    assert "user:usr_alice" in node_ids
    assert "user:usr_rogue" in node_ids
    assert "device:fp_foreign_box" in node_ids
    assert "ip:198.51.100.22" in node_ids

    # CAM-PARKING and Charlie should not be included
    assert "camera:CAM-PARKING" not in node_ids
    assert "user:usr_charlie" not in node_ids


def test_nonexistent_entity_returns_empty_graph():
    graph = IdentityGraph()
    res = graph.get_user_subgraph("ghost_user")
    assert res.total_nodes == 0
    assert res.total_edges == 0

    res_cam = graph.get_camera_subgraph("CAM-999")
    assert res_cam.total_nodes == 0
    assert res_cam.total_edges == 0


def test_graph_endpoint_with_database(db_session: Session):
    now = datetime.now(timezone.utc)
    ev1 = _make_event(
        user_id="usr_dave",
        username="dave",
        device_fp="fp_admin",
        ip_address="10.0.0.5",
        camera_id="CAM-DATA-CENTER",
        timestamp=now - timedelta(hours=2),
    )
    ev2 = _make_event(
        user_id="usr_dave",
        username="dave",
        device_fp="fp_admin",
        ip_address="10.0.0.5",
        camera_id="CAM-DATA-CENTER",
        timestamp=now - timedelta(hours=1),
    )
    db_session.add(ev1)
    db_session.add(ev2)
    db_session.commit()

    # Query endpoint function directly
    resp = get_identity_graph(db=db_session, user_id="usr_dave", days=7)
    assert isinstance(resp, GraphResponse)
    assert resp.total_nodes == 4
    assert any(n.id == "user:usr_dave" for n in resp.nodes)
    assert any(n.id == "camera:CAM-DATA-CENTER" for n in resp.nodes)
