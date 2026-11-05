/**
 * Cybersecurity Analytics API Client with graceful offline fallback.
 *
 * Connects to the FastAPI backend at http://localhost:8001/api/v1.
 * If the backend is offline or unreachable, seamlessly falls back to
 * local mock data and maintains state in-memory so all UI interactions
 * (acknowledge, resolve, filtering, identity graph) function without errors.
 */

export type AlertSeverity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved";

export interface CyberAlert {
  id: string;
  created_at: string;
  rule_id: string;
  severity: AlertSeverity;
  status: AlertStatus;
  entity_type: "user" | "ip" | "camera";
  entity_id: string;
  user_id: string | null;
  ip_address: string | null;
  camera_id: string | null;
  confidence: number;
  explanation: string;
  evidence: Record<string, any> | null;
}

export interface AlertSummaryStats {
  total_alerts: number;
  open_alerts: number;
  acknowledged_alerts: number;
  resolved_alerts: number;
  by_severity: Record<string, number>;
  by_rule: Record<string, number>;
  by_status: Record<string, number>;
  top_suspicious_ips: Array<{ ip_address: string; alert_count: number }>;
  top_suspicious_users: Array<{ user_id: string; alert_count: number }>;
}

export interface GraphNode {
  id: string;
  type: "user" | "device" | "ip" | "camera";
  label: string;
  entity_id: string;
  event_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: "USED_DEVICE" | "USED_IP" | "ACCESSED_CAMERA";
  weight: number;
  last_seen?: string | null;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
}

export interface CameraCyberHealth {
  camera_id: string;
  name: string;
  location: string;
  status: "healthy" | "warning" | "tampered" | "offline";
  last_heartbeat: string;
  heartbeat_age_seconds: number;
  unauthorized_attempts: number;
  active_alerts: number;
  stream_secure: boolean;
}

export interface BackendStatus {
  online: boolean;
  url: string;
  message?: string;
  checked_at: string;
}

const BACKEND_BASE_URL =
  (typeof window !== "undefined" && (window as any).__CYBER_API_URL__) ||
  "http://localhost:8001/api/v1";

const ADMIN_API_KEY = "dev-admin-key";

// ============================================================================
// IN-MEMORY FALLBACK MOCK DATA STORE
// ============================================================================

const INITIAL_MOCK_ALERTS: CyberAlert[] = [
  {
    id: "alt-001",
    created_at: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    rule_id: "RULE_CAMERA_TAMPERING",
    severity: "critical",
    status: "open",
    entity_type: "camera",
    entity_id: "CAM-007",
    user_id: null,
    ip_address: "185.220.101.4",
    camera_id: "CAM-007",
    confidence: 0.98,
    explanation: "Camera tampering detected: camera 'CAM-007' heartbeat missing for 240s (timeout 180s) followed by unauthorized RTSP handshake attempt.",
    evidence: {
      trigger: "HEARTBEAT_MISSING",
      timeout_seconds: 180,
      elapsed_seconds: 240,
      suspected_ip: "185.220.101.4",
      last_heartbeat: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    },
  },
  {
    id: "alt-002",
    created_at: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
    rule_id: "RULE_BRUTE_FORCE",
    severity: "high",
    status: "open",
    entity_type: "ip",
    entity_id: "45.155.205.9",
    user_id: "admin",
    ip_address: "45.155.205.9",
    camera_id: null,
    confidence: 0.94,
    explanation: "Brute force authentication attack: 14 failed logins observed from IP 45.155.205.9 against user 'admin' in 45s.",
    evidence: {
      failed_count: 14,
      target_user: "admin",
      window_seconds: 60,
      user_agent: "masscan/1.3 (Security Scanner)",
    },
  },
  {
    id: "alt-003",
    created_at: new Date(Date.now() - 24 * 60 * 1000).toISOString(),
    rule_id: "ML_ANOMALY",
    severity: "high",
    status: "acknowledged",
    entity_type: "user",
    entity_id: "usr_alice",
    user_id: "usr_alice",
    ip_address: "203.0.113.88",
    camera_id: "CAM-014",
    confidence: 0.89,
    explanation: "ML Behavioral Anomaly (IsolationForest score 0.89): Sudden access from foreign subnet and unverified device fingerprint.",
    evidence: {
      ml_score: 0.892,
      top_reasons: [
        "Unrecognized device fingerprint (fp_unknown_darwin_arm)",
        "New IP subnet 203.0.113.0/24",
        "Off-hours access at 03:22 UTC",
      ],
      user_baseline_deviation: "High",
    },
  },
  {
    id: "alt-004",
    created_at: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
    rule_id: "RULE_CREDENTIAL_STUFFING",
    severity: "critical",
    status: "open",
    entity_type: "ip",
    entity_id: "198.51.100.44",
    user_id: null,
    ip_address: "198.51.100.44",
    camera_id: null,
    confidence: 0.96,
    explanation: "Credential stuffing campaign: single IP failing authentication across 6 distinct operator accounts within 90s.",
    evidence: {
      targeted_usernames: ["admin", "j.mehta", "operator2", "s.khan", "supervisor", "root"],
      attempts: 18,
      source_asn: "AS208843",
    },
  },
  {
    id: "alt-005",
    created_at: new Date(Date.now() - 65 * 60 * 1000).toISOString(),
    rule_id: "RULE_MASS_EXPORT",
    severity: "medium",
    status: "open",
    entity_type: "user",
    entity_id: "usr_bob",
    user_id: "usr_bob",
    ip_address: "10.0.4.22",
    camera_id: "CAM-011",
    confidence: 0.83,
    explanation: "Mass video export threshold exceeded: 22 high-resolution video streams requested in under 6 minutes.",
    evidence: {
      video_count: 22,
      total_bytes_mb: 1840,
      window_seconds: 360,
    },
  },
  {
    id: "alt-006",
    created_at: new Date(Date.now() - 95 * 60 * 1000).toISOString(),
    rule_id: "RULE_PRIVILEGE_ABUSE",
    severity: "medium",
    status: "resolved",
    entity_type: "user",
    entity_id: "usr_carol",
    user_id: "usr_carol",
    ip_address: "10.0.1.45",
    camera_id: "CAM-019",
    confidence: 0.78,
    explanation: "Repeated permission denied: 7 attempts to modify camera PTZ presets and encryption parameters without admin authorization.",
    evidence: {
      denial_count: 7,
      endpoint_attempted: "PATCH /api/v1/cameras/CAM-019/ptz",
    },
  },
  {
    id: "alt-007",
    created_at: new Date(Date.now() - 140 * 60 * 1000).toISOString(),
    rule_id: "RULE_IMPOSSIBLE_ACCESS",
    severity: "high",
    status: "resolved",
    entity_type: "user",
    entity_id: "j.mehta",
    user_id: "j.mehta",
    ip_address: "91.240.118.2",
    camera_id: "CAM-021",
    confidence: 0.91,
    explanation: "Impossible geo-travel: active session authenticated simultaneously from 10.0.1.12 (Internal LAN) and 91.240.118.2 (External WAN) within 3 minutes.",
    evidence: {
      ip_primary: "10.0.1.12",
      ip_secondary: "91.240.118.2",
      delta_seconds: 180,
    },
  },
  {
    id: "alt-008",
    created_at: new Date(Date.now() - 190 * 60 * 1000).toISOString(),
    rule_id: "RULE_CAMERA_TAMPERING",
    severity: "low",
    status: "resolved",
    entity_type: "camera",
    entity_id: "CAM-003",
    user_id: null,
    ip_address: null,
    camera_id: "CAM-003",
    confidence: 0.72,
    explanation: "Intermittent heartbeat jitter: 2 heartbeat frames delayed by network latency (recovered).",
    evidence: {
      dropped_frames: 2,
      jitter_ms: 820,
    },
  },
];

let mockAlertsStore: CyberAlert[] = [...INITIAL_MOCK_ALERTS];

const MOCK_GRAPH: GraphResponse = {
  total_nodes: 18,
  total_edges: 22,
  nodes: [
    // Users
    { id: "u:admin", type: "user", label: "admin", entity_id: "admin", event_count: 58, first_seen: "2026-11-01T08:00:00Z", last_seen: "2026-11-04T10:15:00Z" },
    { id: "u:usr_alice", type: "user", label: "alice_soc", entity_id: "usr_alice", event_count: 42, first_seen: "2026-11-01T09:00:00Z", last_seen: "2026-11-04T09:45:00Z" },
    { id: "u:usr_bob", type: "user", label: "bob_analyst", entity_id: "usr_bob", event_count: 35, first_seen: "2026-11-01T09:30:00Z", last_seen: "2026-11-04T08:50:00Z" },
    { id: "u:usr_carol", type: "user", label: "carol_ops", entity_id: "usr_carol", event_count: 21, first_seen: "2026-11-02T11:00:00Z", last_seen: "2026-11-04T07:20:00Z" },
    { id: "u:j.mehta", type: "user", label: "j.mehta (Lead)", entity_id: "j.mehta", event_count: 64, first_seen: "2026-11-01T07:45:00Z", last_seen: "2026-11-04T10:20:00Z" },
    // Devices
    { id: "d:soc_workstation_1", type: "device", label: "SOC-WS-01", entity_id: "fp_ws01", event_count: 75 },
    { id: "d:soc_workstation_2", type: "device", label: "SOC-WS-02", entity_id: "fp_ws02", event_count: 48 },
    { id: "d:foreign_laptop", type: "device", label: "Alien-Darwin-M3", entity_id: "fp_alien_m3", event_count: 14, metadata: { compromised: true } },
    { id: "d:mobile_terminal", type: "device", label: "Sec-Tablet-04", entity_id: "fp_tablet04", event_count: 26 },
    // IPs
    { id: "ip:10.0.1.15", type: "ip", label: "10.0.1.15 (SOC LAN)", entity_id: "10.0.1.15", event_count: 82 },
    { id: "ip:10.0.4.22", type: "ip", label: "10.0.4.22 (Internal)", entity_id: "10.0.4.22", event_count: 39 },
    { id: "ip:45.155.205.9", type: "ip", label: "45.155.205.9 [MALICIOUS]", entity_id: "45.155.205.9", event_count: 24, metadata: { threat_level: "high" } },
    { id: "ip:185.220.101.4", type: "ip", label: "185.220.101.4 [TOR/VPN]", entity_id: "185.220.101.4", event_count: 31, metadata: { threat_level: "critical" } },
    { id: "ip:203.0.113.88", type: "ip", label: "203.0.113.88 [EXTERNAL]", entity_id: "203.0.113.88", event_count: 18 },
    // Cameras
    { id: "c:CAM-007", type: "camera", label: "CAM-007 (Fence Line)", entity_id: "CAM-007", event_count: 45, metadata: { alert: "Tamper/Offline" } },
    { id: "c:CAM-014", type: "camera", label: "CAM-014 (Lobby Main)", entity_id: "CAM-014", event_count: 110 },
    { id: "c:CAM-011", type: "camera", label: "CAM-011 (Server Room)", entity_id: "CAM-011", event_count: 67 },
    { id: "c:CAM-021", type: "camera", label: "CAM-021 (Corridor 4)", entity_id: "CAM-021", event_count: 53 },
  ],
  edges: [
    // Users to Devices
    { source: "u:admin", target: "d:soc_workstation_1", relation: "USED_DEVICE", weight: 38 },
    { source: "u:j.mehta", target: "d:soc_workstation_1", relation: "USED_DEVICE", weight: 45 },
    { source: "u:usr_alice", target: "d:soc_workstation_2", relation: "USED_DEVICE", weight: 30 },
    { source: "u:usr_alice", target: "d:foreign_laptop", relation: "USED_DEVICE", weight: 8 },
    { source: "u:usr_bob", target: "d:mobile_terminal", relation: "USED_DEVICE", weight: 22 },
    { source: "u:usr_carol", target: "d:soc_workstation_2", relation: "USED_DEVICE", weight: 16 },

    // Devices to IPs
    { source: "d:soc_workstation_1", target: "ip:10.0.1.15", relation: "USED_IP", weight: 65 },
    { source: "d:soc_workstation_2", target: "ip:10.0.1.15", relation: "USED_IP", weight: 40 },
    { source: "d:mobile_terminal", target: "ip:10.0.4.22", relation: "USED_IP", weight: 25 },
    { source: "d:foreign_laptop", target: "ip:203.0.113.88", relation: "USED_IP", weight: 12 },

    // Malicious external IPs touching users/cameras
    { source: "ip:45.155.205.9", target: "u:admin", relation: "USED_IP", weight: 14 },
    { source: "ip:185.220.101.4", target: "c:CAM-007", relation: "ACCESSED_CAMERA", weight: 9 },
    { source: "ip:185.220.101.4", target: "c:CAM-021", relation: "ACCESSED_CAMERA", weight: 6 },

    // Users and IPs accessing cameras
    { source: "u:admin", target: "c:CAM-011", relation: "ACCESSED_CAMERA", weight: 18 },
    { source: "u:j.mehta", target: "c:CAM-014", relation: "ACCESSED_CAMERA", weight: 42 },
    { source: "u:usr_alice", target: "c:CAM-014", relation: "ACCESSED_CAMERA", weight: 19 },
    { source: "u:usr_bob", target: "c:CAM-011", relation: "ACCESSED_CAMERA", weight: 24 },
    { source: "u:usr_carol", target: "c:CAM-021", relation: "ACCESSED_CAMERA", weight: 11 },
    { source: "ip:10.0.1.15", target: "c:CAM-014", relation: "ACCESSED_CAMERA", weight: 50 },
    { source: "ip:10.0.1.15", target: "c:CAM-011", relation: "ACCESSED_CAMERA", weight: 32 },
    { source: "ip:10.0.4.22", target: "c:CAM-011", relation: "ACCESSED_CAMERA", weight: 20 },
    { source: "ip:203.0.113.88", target: "c:CAM-014", relation: "ACCESSED_CAMERA", weight: 5 },
  ],
};

const MOCK_CAMERA_HEALTH: CameraCyberHealth[] = [
  {
    camera_id: "CAM-014",
    name: "Lobby Main",
    location: "Building A · Ground",
    status: "healthy",
    last_heartbeat: new Date(Date.now() - 12 * 1000).toISOString(),
    heartbeat_age_seconds: 12,
    unauthorized_attempts: 0,
    active_alerts: 0,
    stream_secure: true,
  },
  {
    camera_id: "CAM-002",
    name: "Gate 1",
    location: "North Perimeter",
    status: "healthy",
    last_heartbeat: new Date(Date.now() - 19 * 1000).toISOString(),
    heartbeat_age_seconds: 19,
    unauthorized_attempts: 1,
    active_alerts: 0,
    stream_secure: true,
  },
  {
    camera_id: "CAM-003",
    name: "Parking B",
    location: "Level -1",
    status: "healthy",
    last_heartbeat: new Date(Date.now() - 32 * 1000).toISOString(),
    heartbeat_age_seconds: 32,
    unauthorized_attempts: 2,
    active_alerts: 0,
    stream_secure: true,
  },
  {
    camera_id: "CAM-011",
    name: "Server Room",
    location: "Building A · L3",
    status: "warning",
    last_heartbeat: new Date(Date.now() - 78 * 1000).toISOString(),
    heartbeat_age_seconds: 78,
    unauthorized_attempts: 8,
    active_alerts: 1,
    stream_secure: true,
  },
  {
    camera_id: "CAM-005",
    name: "Loading Dock",
    location: "East Wing",
    status: "offline",
    last_heartbeat: new Date(Date.now() - 640 * 1000).toISOString(),
    heartbeat_age_seconds: 640,
    unauthorized_attempts: 0,
    active_alerts: 1,
    stream_secure: false,
  },
  {
    camera_id: "CAM-021",
    name: "Corridor 4",
    location: "Building B · L2",
    status: "warning",
    last_heartbeat: new Date(Date.now() - 45 * 1000).toISOString(),
    heartbeat_age_seconds: 45,
    unauthorized_attempts: 6,
    active_alerts: 1,
    stream_secure: true,
  },
  {
    camera_id: "CAM-007",
    name: "Perimeter West",
    location: "Fence Line",
    status: "tampered",
    last_heartbeat: new Date(Date.now() - 250 * 1000).toISOString(),
    heartbeat_age_seconds: 250,
    unauthorized_attempts: 14,
    active_alerts: 2,
    stream_secure: false,
  },
  {
    camera_id: "CAM-019",
    name: "Reception",
    location: "Building B · Ground",
    status: "healthy",
    last_heartbeat: new Date(Date.now() - 15 * 1000).toISOString(),
    heartbeat_age_seconds: 15,
    unauthorized_attempts: 0,
    active_alerts: 0,
    stream_secure: true,
  },
];

// ============================================================================
// API SERVICE IMPLEMENTATION
// ============================================================================

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 2000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

/** Check connectivity to the FastAPI backend */
export async function checkBackendStatus(): Promise<BackendStatus> {
  const url = `${BACKEND_BASE_URL.replace(/\/api\/v1\/?$/, "")}/health`;
  try {
    const res = await fetchWithTimeout(url, { method: "GET" }, 1500);
    if (res.ok) {
      return {
        online: true,
        url: BACKEND_BASE_URL,
        message: "Connected to FastAPI Cyber Analytics Service",
        checked_at: new Date().toISOString(),
      };
    }
  } catch {
    // Offline or network error
  }
  return {
    online: false,
    url: BACKEND_BASE_URL,
    message: "Backend offline — running in local simulated SOC telemetry mode",
    checked_at: new Date().toISOString(),
  };
}

/** Fetch alert list with optional filters */
export async function fetchAlerts(params?: {
  status?: string;
  severity?: string;
  rule_id?: string;
  user_id?: string;
  camera_id?: string;
  limit?: number;
}): Promise<{ alerts: CyberAlert[]; isBackendLive: boolean }> {
  const query = new URLSearchParams();
  if (params?.status && params.status !== "all") query.set("status", params.status);
  if (params?.severity && params.severity !== "all") query.set("severity", params.severity);
  if (params?.rule_id) query.set("rule_id", params.rule_id);
  if (params?.user_id) query.set("user_id", params.user_id);
  if (params?.camera_id) query.set("camera_id", params.camera_id);
  if (params?.limit) query.set("limit", String(params.limit));

  const url = `${BACKEND_BASE_URL}/alerts?${query.toString()}`;

  try {
    const res = await fetchWithTimeout(url, {
      headers: { "X-Admin-Key": ADMIN_API_KEY, Accept: "application/json" },
    }, 2000);

    if (res.ok) {
      const liveAlerts = await res.json();
      return { alerts: liveAlerts, isBackendLive: true };
    }
  } catch {
    // Fall back to local mock data
  }

  // Filter in-memory mock alerts
  let filtered = [...mockAlertsStore];
  if (params?.status && params.status !== "all") {
    filtered = filtered.filter((a) => a.status === params.status);
  }
  if (params?.severity && params.severity !== "all") {
    filtered = filtered.filter((a) => a.severity.toLowerCase() === params.severity?.toLowerCase());
  }
  if (params?.rule_id) {
    filtered = filtered.filter((a) => a.rule_id === params.rule_id);
  }
  if (params?.user_id) {
    filtered = filtered.filter((a) => a.user_id === params.user_id);
  }
  if (params?.camera_id) {
    filtered = filtered.filter((a) => a.camera_id === params.camera_id);
  }

  return { alerts: filtered, isBackendLive: false };
}

/** Update alert status (open -> acknowledged -> resolved) */
export async function updateAlertStatus(
  alertId: string,
  newStatus: AlertStatus
): Promise<{ success: boolean; alert: CyberAlert; isBackendLive: boolean }> {
  const url = `${BACKEND_BASE_URL}/alerts/${alertId}/status`;

  try {
    const res = await fetchWithTimeout(url, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Key": ADMIN_API_KEY,
      },
      body: JSON.stringify({ status: newStatus }),
    }, 2000);

    if (res.ok) {
      const updated = await res.json();
      // Keep local store in sync
      mockAlertsStore = mockAlertsStore.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a));
      return { success: true, alert: updated, isBackendLive: true };
    }
  } catch {
    // Fall back to local update
  }

  // Update in local mock store
  let updatedAlert: CyberAlert | undefined;
  mockAlertsStore = mockAlertsStore.map((a) => {
    if (a.id === alertId) {
      updatedAlert = { ...a, status: newStatus };
      return updatedAlert;
    }
    return a;
  });

  return {
    success: true,
    alert: updatedAlert || {
      id: alertId,
      created_at: new Date().toISOString(),
      rule_id: "RULE_SYSTEM",
      severity: "low",
      status: newStatus,
      entity_type: "user",
      entity_id: "unknown",
      user_id: null,
      ip_address: null,
      camera_id: null,
      confidence: 1.0,
      explanation: "Local status update applied",
      evidence: null,
    },
    isBackendLive: false,
  };
}

/** Fetch alert summary KPIs */
export async function fetchAlertSummary(days = 7): Promise<{ summary: AlertSummaryStats; isBackendLive: boolean }> {
  const url = `${BACKEND_BASE_URL}/alerts/stats/summary?days=${days}`;

  try {
    const res = await fetchWithTimeout(url, {
      headers: { "X-Admin-Key": ADMIN_API_KEY, Accept: "application/json" },
    }, 2000);

    if (res.ok) {
      const liveSummary = await res.json();
      return { summary: liveSummary, isBackendLive: true };
    }
  } catch {
    // Fall back
  }

  // Calculate stats from mockAlertsStore
  const total = mockAlertsStore.length;
  const open = mockAlertsStore.filter((a) => a.status === "open").length;
  const acknowledged = mockAlertsStore.filter((a) => a.status === "acknowledged").length;
  const resolved = mockAlertsStore.filter((a) => a.status === "resolved").length;

  const by_severity: Record<string, number> = {};
  const by_rule: Record<string, number> = {};
  const by_status: Record<string, number> = {};
  const ip_counts: Record<string, number> = {};
  const user_counts: Record<string, number> = {};

  for (const a of mockAlertsStore) {
    by_severity[a.severity] = (by_severity[a.severity] || 0) + 1;
    by_rule[a.rule_id] = (by_rule[a.rule_id] || 0) + 1;
    by_status[a.status] = (by_status[a.status] || 0) + 1;
    if (a.ip_address) ip_counts[a.ip_address] = (ip_counts[a.ip_address] || 0) + 1;
    if (a.user_id) user_counts[a.user_id] = (user_counts[a.user_id] || 0) + 1;
  }

  const top_suspicious_ips = Object.entries(ip_counts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([ip_address, alert_count]) => ({ ip_address, alert_count }));

  const top_suspicious_users = Object.entries(user_counts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([user_id, alert_count]) => ({ user_id, alert_count }));

  return {
    summary: {
      total_alerts: total,
      open_alerts: open,
      acknowledged_alerts: acknowledged,
      resolved_alerts: resolved,
      by_severity,
      by_rule,
      by_status,
      top_suspicious_ips,
      top_suspicious_users,
    },
    isBackendLive: false,
  };
}

/** Fetch Identity Graph nodes and edges */
export async function fetchIdentityGraph(params?: {
  user_id?: string;
  camera_id?: string;
  days?: number;
}): Promise<{ graph: GraphResponse; isBackendLive: boolean }> {
  const query = new URLSearchParams();
  if (params?.user_id) query.set("user_id", params.user_id);
  if (params?.camera_id) query.set("camera_id", params.camera_id);
  if (params?.days) query.set("days", String(params.days));

  const url = `${BACKEND_BASE_URL}/graph/identity?${query.toString()}`;

  try {
    const res = await fetchWithTimeout(url, {
      headers: { "X-Admin-Key": ADMIN_API_KEY, Accept: "application/json" },
    }, 2000);

    if (res.ok) {
      const liveGraph = await res.json();
      return { graph: liveGraph, isBackendLive: true };
    }
  } catch {
    // Fall back
  }

  // If filtered by user_id or camera_id in mock mode, return subgraph
  if (params?.user_id) {
    const uid = params.user_id.startsWith("u:") ? params.user_id : `u:${params.user_id}`;
    const connectedEdges = MOCK_GRAPH.edges.filter((e) => e.source === uid || e.target === uid);
    const neighborIds = new Set<string>([uid, ...connectedEdges.map((e) => (e.source === uid ? e.target : e.source))]);

    // 2-hop expansion
    const hop2Edges = MOCK_GRAPH.edges.filter((e) => neighborIds.has(e.source) || neighborIds.has(e.target));
    const allNodeIds = new Set<string>([...neighborIds, ...hop2Edges.map((e) => e.source), ...hop2Edges.map((e) => e.target)]);

    const nodes = MOCK_GRAPH.nodes.filter((n) => allNodeIds.has(n.id));
    return {
      graph: {
        nodes,
        edges: hop2Edges,
        total_nodes: nodes.length,
        total_edges: hop2Edges.length,
      },
      isBackendLive: false,
    };
  }

  if (params?.camera_id) {
    const cid = params.camera_id.startsWith("c:") ? params.camera_id : `c:${params.camera_id}`;
    const connectedEdges = MOCK_GRAPH.edges.filter((e) => e.source === cid || e.target === cid);
    const neighborIds = new Set<string>([cid, ...connectedEdges.map((e) => (e.source === cid ? e.target : e.source))]);

    const hop2Edges = MOCK_GRAPH.edges.filter((e) => neighborIds.has(e.source) || neighborIds.has(e.target));
    const allNodeIds = new Set<string>([...neighborIds, ...hop2Edges.map((e) => e.source), ...hop2Edges.map((e) => e.target)]);

    const nodes = MOCK_GRAPH.nodes.filter((n) => allNodeIds.has(n.id));
    return {
      graph: {
        nodes,
        edges: hop2Edges,
        total_nodes: nodes.length,
        total_edges: hop2Edges.length,
      },
      isBackendLive: false,
    };
  }

  return { graph: MOCK_GRAPH, isBackendLive: false };
}

/** Fetch camera cyber health and status telemetry */
export async function fetchCameraCyberHealth(): Promise<CameraCyberHealth[]> {
  // Sync with current mock alerts in case statuses have changed
  return MOCK_CAMERA_HEALTH.map((cam) => {
    const camAlerts = mockAlertsStore.filter(
      (a) => a.camera_id === cam.camera_id && a.status !== "resolved"
    );
    const isCritical = camAlerts.some((a) => a.severity === "critical");
    const isWarning = camAlerts.some((a) => a.severity === "high" || a.severity === "medium");

    let status: CameraCyberHealth["status"] = "healthy";
    if (isCritical || cam.camera_id === "CAM-007") {
      status = "tampered";
    } else if (cam.camera_id === "CAM-005") {
      status = "offline";
    } else if (isWarning || camAlerts.length > 0) {
      status = "warning";
    }

    return {
      ...cam,
      status,
      active_alerts: camAlerts.length,
    };
  });
}

