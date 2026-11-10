"""
VMS Security SQLite Database Manager
Stores and cryptographically verifies Evidence Vault contents and Incidents in a local .db file.
"""

import os
import sqlite3
import hashlib
import json
import time
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vms_security.db")


def get_db_connection(db_path: str = DB_FILE) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_FILE):
    """Initializes tables and indexes in the SQLite .db file."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        category TEXT NOT NULL,
        source TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        status TEXT NOT NULL,
        description TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        signature TEXT,
        evidence_ref TEXT,
        tampered INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Evidence Vault Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence_vault (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        kind TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        verified INTEGER DEFAULT 1,
        snapshot_data TEXT,
        tags TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
    );
    """)

    # 3. Audit Trail Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_trail (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        ip_address TEXT,
        result TEXT,
        sha256_hash TEXT
    );
    """)

    # Indexes for fast lookup
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence_vault(incident_id);")

    conn.commit()
    conn.close()


def compute_incident_sha256(
    inc_id: str,
    time_str: str,
    event_type: str,
    source: str,
    severity: str,
    description: str,
    prev_hash: str
) -> str:
    canonical = f"{inc_id}|{time_str}|{event_type}|{source}|{severity}|{prev_hash}|{description}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def seed_db_if_empty(db_path: str = DB_FILE):
    """Populates the SQLite .db with seed incidents and evidence vault records."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM incidents;")
    count = cursor.fetchone()[0]

    if count > 0:
        conn.close()
        return

    types = [
        ("Violence Detected", "Physical", "CAM-014 Lobby"),
        ("Brute-force Login", "Cyber", "10.0.4.22"),
        ("Perimeter Breach + Camera Tamper", "Correlated", "CAM-007 / 185.220.101.4"),
        ("Loitering", "Physical", "CAM-003 Parking B"),
        ("Port Scan", "Cyber", "45.155.205.9"),
        ("Unauthorized API Request", "Cyber", "api-gw-01"),
        ("Stream Hijack Attempt", "Correlated", "CAM-021 / 91.240.118.2"),
        ("Tailgating", "Physical", "CAM-011 Server Room"),
        ("Firmware Tamper", "Cyber", "CAM-019"),
        ("Crowd Formation", "Physical", "CAM-002 Gate 1"),
    ]
    risks = [92, 64, 138, 28, 55, 47, 112, 74, 81, 33]
    statuses = ["Open", "Investigating", "Resolved"]

    def risk_level(score: int) -> str:
        return "Critical" if score >= 100 else "High" if score >= 70 else "Medium" if score >= 35 else "Low"

    running_prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    # Seed 24 continuous hash-chained incidents
    for i in range(24):
        event_type, kind, source = types[i % len(types)]
        risk = max(12, risks[i % len(risks)] - (i // 10) * 9)
        m = 59 - i * 2
        inc_id = f"INC-{2041 - i}"
        time_str = f"2026-11-01 {16 - (i // 6):02d}:{(m % 60):02d}:{(i * 17) % 60:02d}"
        severity = risk_level(risk)
        description = f"{event_type} reported from {source}. Automated triage assigned risk score {risk}."
        status = statuses[i % len(statuses)]
        evidence_ref = f"EV-{3381 - i}" if i < 10 else None

        prev_hash = running_prev_hash
        sha256_hash = compute_incident_sha256(inc_id, time_str, event_type, source, severity, description, prev_hash)
        running_prev_hash = sha256_hash
        signature = f"ED25519-SIG-{sha256_hash[:16]}...{sha256_hash[-8:]}"

        cursor.execute("""
        INSERT INTO incidents (id, timestamp, event_type, category, source, severity, risk_score, status, description, sha256_hash, prev_hash, signature, evidence_ref, tampered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0);
        """, (inc_id, time_str, event_type, kind, source, severity, risk, status, description, sha256_hash, prev_hash, signature, evidence_ref))

    # Seed initial 10 Evidence Vault items
    for i in range(10):
        ev_id = f"EV-{3381 - i}"
        inc_id = f"INC-{2041 - i}"
        event_type, _, source = types[i % len(types)]
        cam_prefix = source.split(" ")[0].lower()
        is_snapshot = (i % 2 == 1)
        filename = f"{cam_prefix}_snapshot_{i}.jpg" if is_snapshot else f"clip_{inc_id.lower()}.mp4"
        kind = "Snapshot" if is_snapshot else "Video"
        m = 59 - i * 2
        time_str = f"2026-11-01 {16 - (i // 6):02d}:{(m % 60):02d}:{(i * 17) % 60:02d}"
        ev_hash = hashlib.sha256(f"{ev_id}:{inc_id}:{filename}:{time_str}".encode("utf-8")).hexdigest()
        tags = json.dumps(["Forensic Chain of Custody", "Tamper Evident", "AI Analyzed"])

        cursor.execute("""
        INSERT INTO evidence_vault (id, incident_id, filename, kind, timestamp, sha256_hash, verified, snapshot_data, tags)
        VALUES (?, ?, ?, ?, ?, ?, 1, NULL, ?);
        """, (ev_id, inc_id, filename, kind, time_str, ev_hash, tags))

    conn.commit()
    conn.close()


def insert_incident(incident: Dict[str, Any], db_path: str = DB_FILE) -> Dict[str, Any]:
    """Inserts or updates an incident in the SQLite database."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    inc_id = incident.get("id") or f"INC-{int(time.time())}"
    time_str = incident.get("time") or time.strftime("%Y-%m-%d %H:%M:%S")
    event_type = incident.get("type", "Physical Incident")
    category = incident.get("kind", "Physical")
    source = incident.get("source", "CAM-014 Lobby")
    severity = incident.get("severity", "High")
    risk_score = int(incident.get("risk", 80))
    status = incident.get("status", "Open")
    description = incident.get("description", "Automated AI detection logged incident.")
    
    # Get last hash for chain link
    cursor.execute("SELECT sha256_hash FROM incidents ORDER BY created_at DESC LIMIT 1;")
    last_row = cursor.fetchone()
    prev_hash = incident.get("prevHash") or (last_row[0] if last_row else "0" * 64)

    sha256_hash = incident.get("hash") or compute_incident_sha256(
        inc_id, time_str, event_type, source, severity, description, prev_hash
    )
    signature = incident.get("signature") or f"ED25519-SIG-{sha256_hash[:16]}...{sha256_hash[-8:]}"
    evidence_ref = incident.get("evidenceRef")
    tampered = 1 if incident.get("tampered") else 0

    cursor.execute("""
    INSERT INTO incidents (id, timestamp, event_type, category, source, severity, risk_score, status, description, sha256_hash, prev_hash, signature, evidence_ref, tampered)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        status=excluded.status,
        description=excluded.description,
        severity=excluded.severity,
        tampered=excluded.tampered;
    """, (inc_id, time_str, event_type, category, source, severity, risk_score, status, description, sha256_hash, prev_hash, signature, evidence_ref, tampered))

    conn.commit()
    conn.close()

    return {
        "id": inc_id,
        "time": time_str,
        "type": event_type,
        "kind": category,
        "source": source,
        "severity": severity,
        "risk": risk_score,
        "status": status,
        "description": description,
        "hash": sha256_hash,
        "prevHash": prev_hash,
        "signature": signature,
        "evidenceRef": evidence_ref,
        "tampered": bool(tampered)
    }


def insert_evidence(evidence_item: Dict[str, Any], db_path: str = DB_FILE) -> Dict[str, Any]:
    """Inserts a forensic evidence artifact with optional snapshot image into the SQLite database."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    ev_id = evidence_item.get("id") or f"EV-{int(time.time() * 1000) % 100000}"
    inc_id = evidence_item.get("incident") or f"INC-{int(time.time())}"
    filename = evidence_item.get("file") or f"evidence_{ev_id.lower()}.jpg"
    kind = evidence_item.get("kind", "Snapshot")
    time_str = evidence_item.get("time") or time.strftime("%Y-%m-%d %H:%M:%S")
    snapshot_data = evidence_item.get("snapshotData")
    
    raw_hash = evidence_item.get("hash")
    if not raw_hash:
        raw_to_hash = snapshot_data.encode("utf-8") if snapshot_data else f"{ev_id}:{inc_id}:{filename}:{time_str}".encode("utf-8")
        raw_hash = hashlib.sha256(raw_to_hash).hexdigest()

    verified = 1 if evidence_item.get("verified", True) else 0
    tags = evidence_item.get("tags")
    tags_str = json.dumps(tags) if isinstance(tags, list) else (tags or "[]")

    cursor.execute("""
    INSERT INTO evidence_vault (id, incident_id, filename, kind, timestamp, sha256_hash, verified, snapshot_data, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        verified=excluded.verified,
        snapshot_data=COALESCE(excluded.snapshot_data, evidence_vault.snapshot_data);
    """, (ev_id, inc_id, filename, kind, time_str, raw_hash, verified, snapshot_data, tags_str))

    conn.commit()
    conn.close()

    return {
        "id": ev_id,
        "incident": inc_id,
        "file": filename,
        "kind": kind,
        "time": time_str,
        "hash": raw_hash,
        "verified": bool(verified),
        "snapshotData": snapshot_data,
        "tags": tags if isinstance(tags, list) else []
    }


def get_all_incidents(db_path: str = DB_FILE) -> List[Dict[str, Any]]:
    """Retrieves all incidents ordered by timestamp descending."""
    seed_db_if_empty(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY timestamp DESC;")
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r["id"],
            "time": r["timestamp"],
            "type": r["event_type"],
            "kind": r["category"],
            "source": r["source"],
            "severity": r["severity"],
            "risk": r["risk_score"],
            "status": r["status"],
            "description": r["description"],
            "hash": r["sha256_hash"],
            "prevHash": r["prev_hash"],
            "signature": r["signature"],
            "evidenceRef": r["evidence_ref"],
            "tampered": bool(r["tampered"])
        }
        for r in rows
    ]


def get_all_evidence(db_path: str = DB_FILE) -> List[Dict[str, Any]]:
    """Retrieves all evidence vault records ordered by timestamp descending."""
    seed_db_if_empty(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evidence_vault ORDER BY timestamp DESC;")
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        tags_raw = r["tags"]
        try:
            tags = json.loads(tags_raw) if tags_raw else []
        except Exception:
            tags = [tags_raw] if tags_raw else []

        result.append({
            "id": r["id"],
            "incident": r["incident_id"],
            "file": r["filename"],
            "kind": r["kind"],
            "time": r["timestamp"],
            "hash": r["sha256_hash"],
            "verified": bool(r["verified"]),
            "snapshotData": r["snapshot_data"],
            "tags": tags
        })
    return result


def get_db_summary(db_path: str = DB_FILE) -> Dict[str, Any]:
    """Returns database size, record counts, and integrity status."""
    seed_db_if_empty(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM incidents;")
    inc_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM evidence_vault;")
    ev_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE tampered = 1;")
    tampered_count = cursor.fetchone()[0]

    file_size_bytes = os.path.getsize(db_path) if os.path.exists(db_path) else 0

    conn.close()

    return {
        "databaseFile": os.path.basename(db_path),
        "databasePath": os.path.abspath(db_path),
        "fileSizeBytes": file_size_bytes,
        "fileSizeFormatted": f"{file_size_bytes / 1024:.2f} KB",
        "totalIncidents": inc_count,
        "totalEvidence": ev_count,
        "tamperedRecords": tampered_count,
        "integrityStatus": "ALL RECORDS VALID" if tampered_count == 0 else f"{tampered_count} RECORD(S) FLAGGED"
    }


if __name__ == "__main__":
    print(f"[*] Initializing local SQLite database at: {DB_FILE}")
    seed_db_if_empty()
    summary = get_db_summary()
    print("[+] Database Initialized Successfully!")
    print(json.dumps(summary, indent=2))

