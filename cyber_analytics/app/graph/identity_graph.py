"""Identity Graph module: user <-> device <-> IP <-> camera relationship graph.

Uses NetworkX to build, traverse, and filter relationships between security entities,
allowing security operators to inspect:
- Which devices and IP addresses a user has operated from
- Which cameras were accessed by a given user, device, or IP
- The footprint of an IP address across multiple accounts and devices
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

import networkx as nx
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SecurityEvent


class GraphNode(BaseModel):
    """Node in the cybersecurity identity graph."""

    id: str
    type: str  # "user", "device", "ip", "camera"
    label: str
    entity_id: str
    event_count: int = 1
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, Any] = {}


class GraphEdge(BaseModel):
    """Directed or undirected relationship edge."""

    source: str
    target: str
    relation: str  # "USED_DEVICE", "USED_IP", "ACCESSED_CAMERA"
    weight: int = 1
    last_seen: str | None = None


class GraphResponse(BaseModel):
    """Serializable graph payload for frontend visualization."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_nodes: int
    total_edges: int


def _norm_iso(dt: datetime | None) -> str:
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class IdentityGraph:
    """MultiGraph representing interactions between users, devices, IPs, and cameras."""

    def __init__(self):
        self.g: nx.Graph = nx.Graph()

    def add_node(
        self,
        node_id: str,
        *,
        node_type: str,
        label: str,
        entity_id: str,
        timestamp: datetime | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Add or update an entity node with event counters and timestamps."""
        ts_str = _norm_iso(timestamp)
        if self.g.has_node(node_id):
            d = self.g.nodes[node_id]
            d["event_count"] += 1
            if ts_str > d["last_seen"]:
                d["last_seen"] = ts_str
            if ts_str < d["first_seen"]:
                d["first_seen"] = ts_str
            if extra:
                d["metadata"].update(extra)
        else:
            self.g.add_node(
                node_id,
                type=node_type,
                label=label,
                entity_id=entity_id,
                event_count=1,
                first_seen=ts_str,
                last_seen=ts_str,
                metadata=extra or {},
            )

    def add_edge(
        self,
        source: str,
        target: str,
        *,
        relation: str,
        timestamp: datetime | None = None,
    ) -> None:
        """Add or update an edge connecting two entity nodes."""
        ts_str = _norm_iso(timestamp)
        if self.g.has_edge(source, target):
            d = self.g[source][target]
            d["weight"] += 1
            if ts_str > d["last_seen"]:
                d["last_seen"] = ts_str
        else:
            self.g.add_edge(
                source,
                target,
                relation=relation,
                weight=1,
                last_seen=ts_str,
            )

    def ingest_event(self, event: SecurityEvent) -> None:
        """Ingest a single security event and create corresponding nodes and edges."""
        ts = event.timestamp
        u_id = event.user_id or event.username_attempted
        user_node = f"user:{u_id}" if u_id else None
        dev_node = f"device:{event.device_fingerprint}" if event.device_fingerprint else None
        ip_node = f"ip:{event.ip_address}" if event.ip_address else None
        cam_node = f"camera:{event.camera_id}" if event.camera_id else None

        # 1. Add Nodes
        if user_node:
            username_display = event.username_attempted or u_id
            self.add_node(
                user_node,
                node_type="user",
                label=f"User: {username_display}",
                entity_id=u_id,
                timestamp=ts,
                extra={"username": event.username_attempted},
            )

        if dev_node:
            short_fp = event.device_fingerprint[:12] + "..." if len(event.device_fingerprint) > 12 else event.device_fingerprint
            self.add_node(
                dev_node,
                node_type="device",
                label=f"Device: {short_fp}",
                entity_id=event.device_fingerprint,
                timestamp=ts,
            )

        if ip_node:
            short_ip = event.ip_address[:12] + "..." if len(event.ip_address) > 12 else event.ip_address
            # Check masked IP in metadata if available
            masked = (event.event_metadata or {}).get("masked_ip") if isinstance(event.event_metadata, dict) else None
            display_ip = masked or short_ip
            self.add_node(
                ip_node,
                node_type="ip",
                label=f"IP: {display_ip}",
                entity_id=event.ip_address,
                timestamp=ts,
                extra={"masked_ip": masked},
            )

        if cam_node:
            self.add_node(
                cam_node,
                node_type="camera",
                label=f"Camera: {event.camera_id}",
                entity_id=event.camera_id,
                timestamp=ts,
            )

        # 2. Add Edges
        if user_node and dev_node:
            self.add_edge(user_node, dev_node, relation="USED_DEVICE", timestamp=ts)

        if user_node and ip_node:
            self.add_edge(user_node, ip_node, relation="USED_IP", timestamp=ts)

        if dev_node and ip_node:
            self.add_edge(dev_node, ip_node, relation="NETWORK_LINK", timestamp=ts)

        if user_node and cam_node:
            self.add_edge(user_node, cam_node, relation="ACCESSED_CAMERA", timestamp=ts)

        if dev_node and cam_node:
            self.add_edge(dev_node, cam_node, relation="ACCESSED_CAMERA", timestamp=ts)

        if ip_node and cam_node:
            self.add_edge(ip_node, cam_node, relation="ACCESSED_CAMERA", timestamp=ts)

    def to_response(self, subgraph_nodes: set[str] | None = None) -> GraphResponse:
        """Convert NetworkX graph (or filtered node set) to serializable response."""
        nodes_to_export = set(self.g.nodes()) if subgraph_nodes is None else (subgraph_nodes & set(self.g.nodes()))

        node_list: list[GraphNode] = []
        for n_id in nodes_to_export:
            attrs = self.g.nodes[n_id]
            node_list.append(
                GraphNode(
                    id=n_id,
                    type=attrs.get("type", "unknown"),
                    label=attrs.get("label", n_id),
                    entity_id=attrs.get("entity_id", n_id),
                    event_count=attrs.get("event_count", 1),
                    first_seen=attrs.get("first_seen"),
                    last_seen=attrs.get("last_seen"),
                    metadata=attrs.get("metadata", {}),
                )
            )

        edge_list: list[GraphEdge] = []
        for u, v, data in self.g.edges(data=True):
            if u in nodes_to_export and v in nodes_to_export:
                edge_list.append(
                    GraphEdge(
                        source=u,
                        target=v,
                        relation=data.get("relation", "CONNECTED"),
                        weight=data.get("weight", 1),
                        last_seen=data.get("last_seen"),
                    )
                )

        return GraphResponse(
            nodes=node_list,
            edges=edge_list,
            total_nodes=len(node_list),
            total_edges=len(edge_list),
        )

    def get_user_subgraph(self, user_id: str, hops: int = 2) -> GraphResponse:
        """Return subgraph containing user node and all neighbors within N hops."""
        user_node = f"user:{user_id}"
        if not self.g.has_node(user_node):
            return GraphResponse(nodes=[], edges=[], total_nodes=0, total_edges=0)

        # Single-source shortest path lengths up to `hops`
        lengths = nx.single_source_shortest_path_length(self.g, user_node, cutoff=hops)
        subgraph_nodes = set(lengths.keys())
        return self.to_response(subgraph_nodes)

    def get_camera_subgraph(self, camera_id: str, hops: int = 2) -> GraphResponse:
        """Return subgraph containing camera node and all connecting entities within N hops."""
        cam_node = f"camera:{camera_id}"
        if not self.g.has_node(cam_node):
            return GraphResponse(nodes=[], edges=[], total_nodes=0, total_edges=0)

        lengths = nx.single_source_shortest_path_length(self.g, cam_node, cutoff=hops)
        subgraph_nodes = set(lengths.keys())
        return self.to_response(subgraph_nodes)


def build_identity_graph_from_events(events: Sequence[SecurityEvent]) -> IdentityGraph:
    """Build an IdentityGraph from a sequence of SecurityEvent rows."""
    graph = IdentityGraph()
    for e in events:
        graph.ingest_event(e)
    return graph
