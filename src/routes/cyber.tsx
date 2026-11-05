import { useEffect, useState, useMemo, useCallback } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  KeyRound,
  Webhook,
  Activity,
  Radar,
  CameraOff,
  Flame,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Network,
  Cctv,
  Radio,
  Globe,
  User,
  AlertTriangle,
  CheckCircle2,
  ListFilter,
  BarChart2,
  Server,
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  KpiCard,
  PageHeader,
  Panel,
  tooltipStyle,
  axisProps,
  StatusDot,
  chartColors,
} from "@/components/vms/ui";
import { terminalLines, hourly } from "@/lib/mock-data";
import { pageHead } from "@/lib/meta";
import { cn } from "@/lib/utils";
import {
  type CyberAlert,
  type AlertSummaryStats,
  type GraphResponse,
  type CameraCyberHealth,
  type BackendStatus,
  checkBackendStatus,
  fetchAlerts,
  fetchAlertSummary,
  fetchIdentityGraph,
  fetchCameraCyberHealth,
} from "@/lib/cyber-api";
import { CyberAlertsFeed } from "@/components/vms/CyberAlertsFeed";
import { IdentityGraphVisualizer } from "@/components/vms/IdentityGraphVisualizer";
import { CameraCyberHealthView } from "@/components/vms/CameraCyberHealth";

export const Route = createFileRoute("/cyber")({
  head: pageHead(
    "Cybersecurity Monitor",
    "Network, identity, and camera cyber threat telemetry with real-time detection and blast radius analysis."
  ),
  component: Cyber,
});

type ActiveTab = "alerts" | "graph" | "cameras";

function Cyber() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("alerts");
  const [backendStatus, setBackendStatus] = useState<BackendStatus>({
    online: false,
    url: "http://localhost:8001/api/v1",
    checked_at: new Date().toISOString(),
  });

  const [alerts, setAlerts] = useState<CyberAlert[]>([]);
  const [summary, setSummary] = useState<AlertSummaryStats | null>(null);
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [cameraHealth, setCameraHealth] = useState<CameraCyberHealth[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Live Terminal Lines Ticker
  const [lines, setLines] = useState(() => terminalLines.slice(0, 5).map((l, i) => ({ id: i, l })));
  useEffect(() => {
    let n = 5;
    const t = setInterval(() => {
      const ts = new Date().toISOString().slice(11, 19);
      setLines((p) => [...p.slice(-13), { id: n, l: `${ts} ${terminalLines[n % terminalLines.length]}` }]);
      n++;
    }, 2400);
    return () => clearInterval(t);
  }, []);

  // Fetch all cyber data
  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [bStatus, alertsRes, sumRes, graphRes, cams] = await Promise.all([
        checkBackendStatus(),
        fetchAlerts(),
        fetchAlertSummary(),
        fetchIdentityGraph(),
        fetchCameraCyberHealth(),
      ]);

      setBackendStatus(bStatus);
      setAlerts(alertsRes.alerts);
      setSummary(sumRes.summary);
      setGraphData(graphRes.graph);
      setCameraHealth(cams);
    } catch (err) {
      console.error("Failed to load cybersecurity data:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Periodic refresh every 15 seconds
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleAlertUpdated = (updatedAlert: CyberAlert) => {
    setAlerts((prev) => prev.map((a) => (a.id === updatedAlert.id ? updatedAlert : a)));
    // Refresh stats and camera health
    fetchAlertSummary().then((res) => setSummary(res.summary));
    fetchCameraCyberHealth().then(setCameraHealth);
  };

  // Cross-view navigation handlers
  const handleSelectEntityInGraph = (entityType: string, entityId: string) => {
    setActiveTab("graph");
  };

  const handleFilterAlertsByEntity = (entityType: string, entityId: string) => {
    setActiveTab("alerts");
  };

  const handleSelectCameraAlerts = (cameraId: string) => {
    setActiveTab("alerts");
  };

  // Chart data: Rule Breakdown
  const ruleChartData = useMemo(() => {
    if (!summary?.by_rule) return [];
    const ruleFriendlyNames: Record<string, string> = {
      RULE_BRUTE_FORCE: "Brute Force",
      RULE_CREDENTIAL_STUFFING: "Cred Stuffing",
      RULE_IMPOSSIBLE_ACCESS: "Impossible Travel",
      RULE_MASS_EXPORT: "Mass Export",
      RULE_PRIVILEGE_ABUSE: "Privilege Abuse",
      RULE_CAMERA_TAMPERING: "Camera Tamper",
      ML_ANOMALY: "ML Anomaly",
    };

    return Object.entries(summary.by_rule).map(([rule_id, count]) => ({
      name: ruleFriendlyNames[rule_id] || rule_id.replace("RULE_", ""),
      count,
    }));
  }, [summary]);

  // Hourly severity breakdown for AreaChart
  const telemetryHourlyData = useMemo(() => {
    return hourly.map((h, i) => ({
      t: h.t,
      critical: Math.max(0, Math.floor(h.cyber * 0.25) + (i % 3 === 0 ? 2 : 0)),
      high: Math.max(0, Math.floor(h.cyber * 0.4)),
      medium: Math.max(0, Math.floor(h.cyber * 0.35)),
    }));
  }, []);

  const openCount = summary?.open_alerts ?? alerts.filter((a) => a.status === "open").length;
  const ackCount = summary?.acknowledged_alerts ?? alerts.filter((a) => a.status === "acknowledged").length;
  const criticalThreatsCount =
    summary?.by_severity?.critical ??
    alerts.filter((a) => a.severity === "critical" && a.status !== "resolved").length;

  const topSuspiciousIp = summary?.top_suspicious_ips?.[0] ?? { ip_address: "185.220.101.4", alert_count: 3 };
  const topSuspiciousUser = summary?.top_suspicious_users?.[0] ?? { user_id: "admin", alert_count: 2 };

  return (
    <>
      {/* Header and Backend Status Bar */}
      <div className="mb-4">
        <PageHeader
          title="Cybersecurity Monitor"
          subtitle="Network, identity, and device threat telemetry with automated detection and blast radius analysis"
          actions={
            <div className="flex items-center gap-2">
              {/* Backend Live / Fallback Indicator */}
              <div
                className={cn(
                  "flex items-center gap-2 rounded-md border px-3 py-1.5 font-mono text-xs",
                  backendStatus.online
                    ? "border-success/30 bg-success/10 text-success"
                    : "border-warning/30 bg-warning/10 text-warning"
                )}
                title={backendStatus.message}
              >
                <StatusDot tone={backendStatus.online ? "success" : "warning"} />
                <span className="font-semibold">
                  {backendStatus.online ? "BACKEND CONNECTED" : "OFFLINE FALLBACK MODE"}
                </span>
                <span className="text-[10px] opacity-75">
                  ({backendStatus.online ? "http://localhost:8001" : "Simulated SOC Telemetry"})
                </span>
              </div>

              <button
                type="button"
                onClick={loadData}
                disabled={isLoading}
                title="Refresh all cybersecurity telemetry"
                className="flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-accent disabled:opacity-50"
              >
                <RefreshCw className={cn("size-3.5", isLoading && "animate-spin text-primary")} />
                Sync
              </button>
            </div>
          }
        />
      </div>

      {/* KPI & Summary Cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <KpiCard
          label="Open Alerts"
          value={openCount}
          icon={ShieldAlert}
          tone={openCount > 0 ? "critical" : "primary"}
          hint={`${ackCount} acknowledged`}
        />
        <KpiCard
          label="Critical Threats"
          value={criticalThreatsCount}
          icon={Flame}
          tone="critical"
          hint="Requires immediate triage"
        />
        <KpiCard
          label="Top Suspicious IP"
          value={
            <span className="font-mono text-sm font-bold text-cyan">
              {topSuspiciousIp.ip_address}
            </span>
          }
          icon={Globe}
          tone="cyan"
          hint={`${topSuspiciousIp.alert_count} active triggers`}
        />
        <KpiCard
          label="Top Targeted User"
          value={
            <span className="font-mono text-sm font-bold text-warning">
              {topSuspiciousUser.user_id}
            </span>
          }
          icon={User}
          tone="warning"
          hint={`${topSuspiciousUser.alert_count} failed auth events`}
        />
        <KpiCard
          label="Cameras Monitored"
          value={cameraHealth.length || 8}
          icon={Cctv}
          tone="primary"
          hint={`${cameraHealth.filter((c) => c.status === "healthy").length} healthy heartbeats`}
        />
      </div>

      {/* Navigation Tabs */}
      <div className="mt-6 border-b border-border">
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setActiveTab("alerts")}
            className={cn(
              "flex items-center gap-2 border-b-2 px-4 py-2 text-sm font-medium transition-colors",
              activeTab === "alerts"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
            )}
          >
            <ShieldAlert className="size-4" />
            Live Alerts & Telemetry
            <span className="rounded-full bg-primary/20 px-1.5 py-0.2 text-[10px] font-mono font-semibold">
              {alerts.length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("graph")}
            className={cn(
              "flex items-center gap-2 border-b-2 px-4 py-2 text-sm font-medium transition-colors",
              activeTab === "graph"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
            )}
          >
            <Network className="size-4" />
            Identity & Blast Radius Graph
            {graphData && (
              <span className="rounded-full bg-cyan/20 px-1.5 py-0.2 text-[10px] font-mono text-cyan">
                {graphData.total_nodes} nodes
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("cameras")}
            className={cn(
              "flex items-center gap-2 border-b-2 px-4 py-2 text-sm font-medium transition-colors",
              activeTab === "cameras"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
            )}
          >
            <Radio className="size-4" />
            Camera Cyber Health
            <span
              className={cn(
                "rounded-full px-1.5 py-0.2 text-[10px] font-mono",
                cameraHealth.some((c) => c.status === "tampered")
                  ? "bg-critical/20 text-critical font-bold animate-pulse"
                  : "bg-success/20 text-success"
              )}
            >
              {cameraHealth.filter((c) => c.status === "tampered").length > 0 ? "Tamper Alert" : "Normal"}
            </span>
          </button>
        </div>
      </div>

      {/* Tab 1: Live Alerts & Telemetry */}
      {activeTab === "alerts" && (
        <div className="mt-4 space-y-4">
          {/* Telemetry Charts & Live Terminal Grid */}
          <div className="grid gap-4 xl:grid-cols-3">
            {/* Multi-layer Severity AreaChart */}
            <Panel title="Cyber telemetry volume by severity (24h)" className="xl:col-span-2">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={telemetryHourlyData}>
                    <defs>
                      <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--critical)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="var(--critical)" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="warnGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--warning)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="var(--warning)" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--cyan)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="var(--cyan)" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="t" {...axisProps} />
                    <YAxis {...axisProps} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Area
                      type="monotone"
                      dataKey="critical"
                      stroke="var(--critical)"
                      fillOpacity={1}
                      fill="url(#critGrad)"
                      name="Critical Threats"
                    />
                    <Area
                      type="monotone"
                      dataKey="high"
                      stroke="var(--warning)"
                      fillOpacity={1}
                      fill="url(#warnGrad)"
                      name="High Severity"
                    />
                    <Area
                      type="monotone"
                      dataKey="medium"
                      stroke="var(--cyan)"
                      fillOpacity={1}
                      fill="url(#cyanGrad)"
                      name="Medium Severity"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            {/* Detection Rule Breakdown BarChart */}
            <Panel title="Triggered detection rules">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={ruleChartData} layout="vertical" margin={{ left: 15, right: 15 }}>
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" horizontal={false} />
                    <XAxis type="number" {...axisProps} />
                    <YAxis
                      dataKey="name"
                      type="category"
                      {...axisProps}
                      width={100}
                      tick={{ fill: "var(--foreground)", fontSize: 10 }}
                    />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="count" fill="var(--cyan)" radius={[0, 4, 4, 0]}>
                      {ruleChartData.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>
          </div>

          {/* Live Terminal Output Ticker */}
          <Panel title="Live platform event ticker (IDS / Auth / RTSP Handshakes)">
            <div className="h-32 overflow-hidden rounded-md border bg-terminal p-3 font-mono text-xs leading-6">
              {lines.map(({ id, l }) => (
                <p
                  key={id}
                  className={
                    l.includes("[CORR]") || l.includes("DROP")
                      ? "text-critical"
                      : l.includes("[AUTH]")
                      ? "text-warning"
                      : "text-success"
                  }
                >
                  <span className="text-muted-foreground">$ </span>
                  {l}
                </p>
              ))}
              <p className="animate-pulse text-cyan">▋</p>
            </div>
          </Panel>

          {/* Live Alerts Table / Feed with One-Click Acknowledge & Resolve */}
          <Panel title="Security Alerts & Anomaly Feed">
            <CyberAlertsFeed
              alerts={alerts}
              isLoading={isLoading}
              onAlertUpdated={handleAlertUpdated}
              onRefresh={loadData}
              onSelectEntity={handleSelectEntityInGraph}
            />
          </Panel>
        </div>
      )}

      {/* Tab 2: Identity & Blast Radius Graph */}
      {activeTab === "graph" && (
        <div className="mt-4">
          <Panel
            title="Interactive Identity & Device Forensics Graph"
            action={
              <span className="font-mono text-xs text-muted-foreground">
                NetworkX / PostgreSQL Ingest Graph
              </span>
            }
          >
            {graphData ? (
              <IdentityGraphVisualizer
                graph={graphData}
                isLoading={isLoading}
                onRefresh={loadData}
                onFilterAlertsByEntity={handleFilterAlertsByEntity}
              />
            ) : (
              <div className="py-16 text-center text-muted-foreground">Loading identity graph...</div>
            )}
          </Panel>
        </div>
      )}

      {/* Tab 3: Camera Cyber Health */}
      {activeTab === "cameras" && (
        <div className="mt-4">
          <Panel
            title="Camera Cyber Health & Heartbeat Monitor"
            action={
              <span className="font-mono text-xs text-muted-foreground">
                3-min timeout detection
              </span>
            }
          >
            <CameraCyberHealthView
              cameras={cameraHealth}
              isLoading={isLoading}
              onSelectCameraAlerts={handleSelectCameraAlerts}
              onSelectCameraInGraph={(camId) => {
                setActiveTab("graph");
              }}
            />
          </Panel>
        </div>
      )}
    </>
  );
}
