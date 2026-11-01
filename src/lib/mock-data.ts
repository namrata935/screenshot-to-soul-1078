// DEMO DATA — all values are static and simulated.
export type Severity = "Low" | "Medium" | "High" | "Critical";
export type EventKind = "Physical" | "Cyber" | "Correlated";

export const riskLevel = (score: number): Severity =>
  score >= 100 ? "Critical" : score >= 70 ? "High" : score >= 35 ? "Medium" : "Low";

const at = <T,>(a: readonly T[], i: number): T => a[((i % a.length) + a.length) % a.length]!;

export const CORRELATION_WINDOW_SECONDS = 60;
export const CORRELATION_MULTIPLIER = 1.5;
/** Combined risk: sum of both scores, multiplied by 1.5 when events fall within 60s. */
export const correlatedRisk = (physical: number, cyber: number, deltaSeconds: number) =>
  Math.round((physical + cyber) * (Math.abs(deltaSeconds) <= CORRELATION_WINDOW_SECONDS ? CORRELATION_MULTIPLIER : 1));

export interface Incident {
  id: string; time: string; type: string; kind: EventKind; source: string;
  severity: Severity; risk: number; status: "Open" | "Investigating" | "Resolved"; description: string;
}

const types: [string, EventKind, string][] = [
  ["Violence Detected", "Physical", "CAM-014 Lobby"],
  ["Brute-force Login", "Cyber", "10.0.4.22"],
  ["Perimeter Breach + Camera Tamper", "Correlated", "CAM-007 / 185.220.101.4"],
  ["Loitering", "Physical", "CAM-003 Parking B"],
  ["Port Scan", "Cyber", "45.155.205.9"],
  ["Unauthorized API Request", "Cyber", "api-gw-01"],
  ["Stream Hijack Attempt", "Correlated", "CAM-021 / 91.240.118.2"],
  ["Tailgating", "Physical", "CAM-011 Server Room"],
  ["Firmware Tamper", "Cyber", "CAM-019"],
  ["Crowd Formation", "Physical", "CAM-002 Gate 1"],
];
const risks = [92, 64, 138, 28, 55, 47, 112, 74, 81, 33];
const statuses: Incident["status"][] = ["Open", "Investigating", "Resolved"];

export const incidents: Incident[] = Array.from({ length: 24 }, (_, i) => {
  const [type, kind, source] = at(types, i);
  const risk = Math.max(12, at(risks, i) - Math.floor(i / 10) * 9);
  const m = 59 - i * 2;
  return {
    id: `INC-${(2041 - i).toString()}`,
    time: `2026-11-01 ${String(16 - Math.floor(i / 6)).padStart(2, "0")}:${String(((m % 60) + 60) % 60).padStart(2, "0")}:${String((i * 17) % 60).padStart(2, "0")}`,
    type, kind, source, risk, severity: riskLevel(risk),
    status: at(statuses, i),
    description: `${type} reported from ${source}. Automated triage assigned risk score ${risk}.`,
  };
});

export interface Camera { id: string; name: string; location: string; online: boolean; source: "Webcam" | "RTSP"; fps: number }
export const cameras: Camera[] = [
  ["Lobby Main", "Building A · Ground"], ["Gate 1", "North Perimeter"], ["Parking B", "Level -1"],
  ["Server Room", "Building A · L3"], ["Loading Dock", "East Wing"], ["Corridor 4", "Building B · L2"],
  ["Perimeter West", "Fence Line"], ["Reception", "Building B · Ground"],
].map(([name = "", location = ""], i) => ({
  id: `CAM-${String(at([14, 2, 3, 11, 5, 21, 7, 19], i)).padStart(3, "0")}`,
  name, location, online: i !== 4 && i !== 6, source: i % 3 === 0 ? "Webcam" : "RTSP", fps: at([30, 25, 24, 30, 0, 25, 0, 30], i),
}));

export const threatDistribution = [
  { name: "Violence", value: 18 }, { name: "Intrusion", value: 26 }, { name: "Brute-force", value: 31 },
  { name: "Port scan", value: 14 }, { name: "Tamper", value: 11 },
];

export const hourly = Array.from({ length: 12 }, (_, i) => ({
  t: `${String(i * 2).padStart(2, "0")}:00`,
  physical: [4, 3, 2, 2, 5, 9, 12, 10, 8, 11, 7, 5][i],
  cyber: [7, 9, 12, 6, 4, 6, 8, 14, 11, 9, 13, 10][i],
}));

export const trends = {
  daily: hourly.map((h, i) => ({ label: h.t, incidents: h.physical! + h.cyber!, risk: 30 + ((i * 13) % 60), physical: h.physical!, cyber: h.cyber! })),
  weekly: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d, i) => ({
    label: d, incidents: [62, 71, 58, 84, 96, 44, 39][i], risk: [48, 55, 51, 68, 79, 42, 36][i],
    physical: [28, 30, 22, 35, 41, 20, 18][i], cyber: [34, 41, 36, 49, 55, 24, 21][i],
  })),
  monthly: ["Jun", "Jul", "Aug", "Sep", "Oct", "Nov"].map((d, i) => ({
    label: d, incidents: [310, 342, 298, 401, 455, 120][i], risk: [44, 49, 46, 58, 66, 61][i],
    physical: [140, 150, 128, 170, 192, 51][i], cyber: [170, 192, 170, 231, 263, 69][i],
  })),
};

export const severityDist = [
  { name: "Low", value: 42 }, { name: "Medium", value: 31 }, { name: "High", value: 19 }, { name: "Critical", value: 8 },
];

export const cameraStats = cameras.map((c, i) => ({ camera: c.id, events: at([34, 21, 18, 27, 4, 15, 9, 22], i) }));

export const cyberKpis = [
  { label: "Failed Logins", value: 1284, delta: "+12%" },
  { label: "Unauthorized API", value: 327, delta: "+4%" },
  { label: "Suspicious Traffic", value: 89, delta: "-7%" },
  { label: "Port Scans", value: 46, delta: "+21%" },
  { label: "Camera Compromise", value: 3, delta: "+1" },
];

export const cyberEvents = Array.from({ length: 14 }, (_, i) => {
  const ev = ["Failed SSH login", "Unauthorized API call", "Port scan 1-1024", "RTSP auth bypass attempt", "Anomalous egress traffic", "Firmware hash mismatch", "Credential stuffing"][i % 7];
  const sev: Severity[] = ["Medium", "High", "Medium", "Critical", "High", "Critical", "High"];
  return {
    time: `16:${String(58 - i * 3).padStart(2, "0")}:${String((i * 23) % 60).padStart(2, "0")}`,
    event: ev!, ip: ["185.220.101.4", "45.155.205.9", "10.0.4.22", "91.240.118.2", "203.0.113.77", "198.51.100.12", "172.16.9.40"][i % 7],
    severity: at(sev, i), status: i % 3 === 0 ? "Blocked" : i % 3 === 1 ? "Monitoring" : "Mitigated",
  };
});

export const terminalLines = [
  "[IDS] SYN scan detected from 45.155.205.9 → 10.0.2.0/24",
  "[AUTH] 14 failed logins for user 'admin' from 185.220.101.4",
  "[FW] DROP tcp 91.240.118.2:51122 → CAM-021:554",
  "[API] 401 POST /v1/cameras/CAM-019/firmware",
  "[NET] Egress spike 48 MB/s from CAM-007",
  "[CORR] CAM-007 tamper + intrusion within 23s → x1.5",
  "[AUTH] MFA challenge passed for j.mehta",
  "[IDS] Suspicious user-agent 'masscan/1.3'",
  "[FW] Geo-block applied: AS208843",
  "[HASH] Evidence EV-3381 SHA-256 verified",
];

export const correlationPairs = [
  { id: "COR-118", physical: { event: "Perimeter breach", cam: "CAM-007", t: "16:41:02", score: 48 }, cyber: { event: "Camera tamper / RTSP takeover", ip: "185.220.101.4", t: "16:41:25", score: 44 }, delta: 23 },
  { id: "COR-117", physical: { event: "Tailgating", cam: "CAM-011", t: "16:12:40", score: 30 }, cyber: { event: "Badge DB brute-force", ip: "10.0.4.22", t: "16:13:31", score: 26 }, delta: 51 },
  { id: "COR-116", physical: { event: "Loitering", cam: "CAM-003", t: "15:58:10", score: 14 }, cyber: { event: "Port scan", ip: "45.155.205.9", t: "16:00:02", score: 18 }, delta: 112 },
  { id: "COR-115", physical: { event: "Violence", cam: "CAM-014", t: "15:30:05", score: 60 }, cyber: { event: "Stream hijack", ip: "91.240.118.2", t: "15:30:47", score: 38 }, delta: 42 },
];

export const riskProgression = [
  { t: "-60s", risk: 0 }, { t: "-45s", risk: 12 }, { t: "-30s", risk: 48 }, { t: "-23s", risk: 48 },
  { t: "-15s", risk: 92 }, { t: "-5s", risk: 120 }, { t: "0s", risk: 138 },
];

const hex = (seed: number) => {
  let s = "", x = seed * 2654435761;
  for (let i = 0; i < 64; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; s += (x % 16).toString(16); }
  return s;
};
export const evidence = Array.from({ length: 10 }, (_, i) => ({
  id: `EV-${3381 - i}`, incident: at(incidents, i).id,
  file: i % 2 ? `${(at(incidents, i).source.split(" ")[0] ?? "cam").toLowerCase()}_snapshot_${i}.jpg` : `clip_${at(incidents, i).id.toLowerCase()}.mp4`,
  kind: (i % 2 ? "Snapshot" : "Video") as "Snapshot" | "Video",
  time: at(incidents, i).time, hash: hex(i + 7), verified: i % 4 !== 3,
}));

export const auditLogs = Array.from({ length: 30 }, (_, i) => ({
  time: `2026-11-01 ${String(16 - Math.floor(i / 5)).padStart(2, "0")}:${String((59 - i * 7 + 600) % 60).padStart(2, "0")}:${String((i * 31) % 60).padStart(2, "0")}`,
  user: ["j.mehta", "a.rao", "system", "s.khan", "admin"][i % 5],
  action: ["Login", "Viewed camera CAM-014", "Exported evidence EV-3379", "Resolved INC-2038", "Changed RTSP config", "Failed login", "Verified hash EV-3381", "Removed camera CAM-099"][i % 8],
  ip: ["10.0.1.12", "10.0.1.45", "127.0.0.1", "10.0.2.8", "185.220.101.4"][i % 5],
  result: (i % 8 === 5 || i % 11 === 4 ? "Failure" : "Success") as "Success" | "Failure",
}));
