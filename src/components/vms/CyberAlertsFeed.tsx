import { useState } from "react";
import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Eye,
  ChevronDown,
  ChevronUp,
  Search,
  Filter,
  RefreshCw,
  User,
  Globe,
  Camera,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  type CyberAlert,
  type AlertSeverity,
  type AlertStatus,
  updateAlertStatus,
} from "@/lib/cyber-api";
import { SeverityBadge } from "./ui";

interface CyberAlertsFeedProps {
  alerts: CyberAlert[];
  isLoading?: boolean;
  onAlertUpdated: (updatedAlert: CyberAlert) => void;
  onRefresh?: () => void;
  onSelectEntity?: (entityType: string, entityId: string) => void;
}

const severityOrder: Record<AlertSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export function CyberAlertsFeed({
  alerts,
  isLoading = false,
  onAlertUpdated,
  onRefresh,
  onSelectEntity,
}: CyberAlertsFeedProps) {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const handleStatusChange = async (alertId: string, newStatus: AlertStatus) => {
    setUpdatingId(alertId);
    try {
      const res = await updateAlertStatus(alertId, newStatus);
      if (res.success) {
        onAlertUpdated(res.alert);
      }
    } finally {
      setUpdatingId(null);
    }
  };

  const filteredAlerts = alerts
    .filter((a) => {
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (severityFilter !== "all" && a.severity.toLowerCase() !== severityFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          a.rule_id.toLowerCase().includes(q) ||
          a.explanation.toLowerCase().includes(q) ||
          (a.user_id && a.user_id.toLowerCase().includes(q)) ||
          (a.ip_address && a.ip_address.toLowerCase().includes(q)) ||
          (a.camera_id && a.camera_id.toLowerCase().includes(q))
        );
      }
      return true;
    })
    .sort((a, b) => {
      // Prioritize open and critical/high
      if (a.status === "open" && b.status !== "open") return -1;
      if (b.status === "open" && a.status !== "open") return 1;
      return severityOrder[b.severity] - severityOrder[a.severity];
    });

  const openCount = alerts.filter((a) => a.status === "open").length;
  const ackCount = alerts.filter((a) => a.status === "acknowledged").length;
  const resCount = alerts.filter((a) => a.status === "resolved").length;

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-col gap-3 rounded-lg border border-border/70 bg-card p-3 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Tabs */}
          <div className="inline-flex rounded-md border border-border/80 bg-background/50 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setStatusFilter("all")}
              className={cn(
                "rounded px-2.5 py-1 font-medium transition-colors",
                statusFilter === "all" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"
              )}
            >
              All ({alerts.length})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter("open")}
              className={cn(
                "flex items-center gap-1 rounded px-2.5 py-1 font-medium transition-colors",
                statusFilter === "open" ? "bg-critical text-destructive-foreground" : "text-critical hover:bg-critical/10"
              )}
            >
              <span className="size-1.5 rounded-full bg-current" />
              Open ({openCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter("acknowledged")}
              className={cn(
                "rounded px-2.5 py-1 font-medium transition-colors",
                statusFilter === "acknowledged" ? "bg-warning text-black font-semibold" : "text-warning hover:bg-warning/10"
              )}
            >
              Ack ({ackCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter("resolved")}
              className={cn(
                "rounded px-2.5 py-1 font-medium transition-colors",
                statusFilter === "resolved" ? "bg-success text-white" : "text-success hover:bg-success/10"
              )}
            >
              Resolved ({resCount})
            </button>
          </div>

          {/* Severity Dropdown */}
          <div className="flex items-center gap-1.5 text-xs">
            <Filter className="size-3.5 text-muted-foreground" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground focus:border-primary focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        {/* Search & Refresh */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1 md:w-64">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search rule, user, IP, camera..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-md border border-border bg-background py-1 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
            />
          </div>
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={isLoading}
              title="Refresh alert feed"
              className="inline-flex size-7 items-center justify-center rounded-md border border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50"
            >
              <RefreshCw className={cn("size-3.5", isLoading && "animate-spin text-primary")} />
            </button>
          )}
        </div>
      </div>

      {/* Alerts Table / Feed */}
      <div className="overflow-hidden rounded-lg border border-border bg-card">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border bg-muted/30 uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2.5 font-medium">Severity</th>
                <th className="px-3 py-2.5 font-medium">Rule & Explanation</th>
                <th className="px-3 py-2.5 font-medium">Target Entity</th>
                <th className="px-3 py-2.5 font-medium">Confidence</th>
                <th className="px-3 py-2.5 font-medium">Status</th>
                <th className="px-3 py-2.5 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted-foreground">
                    <ShieldAlert className="mx-auto mb-2 size-8 opacity-40 text-cyan" />
                    <p className="font-medium text-foreground">No cybersecurity alerts match this filter</p>
                    <p className="text-[11px] text-muted-foreground">Try clearing filters or search query.</p>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isExpanded = expandedId === alert.id;
                  const isUpdating = updatingId === alert.id;
                  const sevCap = (alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)) as any;
                  const timeFormatted = new Date(alert.created_at).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  });

                  return (
                    <tr
                      key={alert.id}
                      className={cn(
                        "group transition-colors hover:bg-muted/20",
                        alert.status === "open" && alert.severity === "critical" && "bg-critical/5",
                        isExpanded && "bg-muted/30"
                      )}
                    >
                      {/* Severity & Time */}
                      <td className="whitespace-nowrap px-3 py-3 align-top">
                        <div className="flex flex-col gap-1">
                          <SeverityBadge severity={sevCap} />
                          <span className="font-mono text-[10px] text-muted-foreground">{timeFormatted}</span>
                        </div>
                      </td>

                      {/* Rule & Explanation */}
                      <td className="px-3 py-3 align-top">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[11px] font-semibold text-cyan">
                              {alert.rule_id}
                            </span>
                            {alert.rule_id.startsWith("ML_") && (
                              <span className="rounded bg-primary/20 px-1 py-0.5 font-mono text-[9px] text-primary">
                                AI ML
                              </span>
                            )}
                          </div>
                          <p className="text-foreground/90 leading-relaxed">{alert.explanation}</p>

                          {/* Expand Details Toggle */}
                          {alert.evidence && (
                            <button
                              type="button"
                              onClick={() => setExpandedId(isExpanded ? null : alert.id)}
                              className="mt-1 inline-flex items-center gap-1 font-mono text-[10px] text-muted-foreground hover:text-cyan"
                            >
                              {isExpanded ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
                              {isExpanded ? "Hide Evidence" : "Inspect Raw Evidence"}
                            </button>
                          )}

                          {/* Expanded Evidence Details Drawer */}
                          {isExpanded && alert.evidence && (
                            <div className="mt-2 rounded-md border border-border/80 bg-terminal p-2.5 font-mono text-[11px] text-emerald-400">
                              <p className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                                Raw Evidence Payload
                              </p>
                              <pre className="overflow-x-auto whitespace-pre-wrap leading-tight">
                                {JSON.stringify(alert.evidence, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Entities */}
                      <td className="whitespace-nowrap px-3 py-3 align-top">
                        <div className="flex flex-col gap-1">
                          {alert.user_id && (
                            <button
                              type="button"
                              onClick={() => onSelectEntity?.("user", alert.user_id!)}
                              className="inline-flex items-center gap-1 rounded bg-muted/50 px-1.5 py-0.5 text-[11px] font-mono text-foreground hover:border hover:border-cyan hover:text-cyan"
                              title="Inspect user in identity graph"
                            >
                              <User className="size-3 text-cyan" />
                              <span>{alert.user_id}</span>
                            </button>
                          )}
                          {alert.ip_address && (
                            <button
                              type="button"
                              onClick={() => onSelectEntity?.("ip", alert.ip_address!)}
                              className="inline-flex items-center gap-1 rounded bg-muted/50 px-1.5 py-0.5 text-[11px] font-mono text-cyan hover:underline"
                              title="Inspect IP in identity graph"
                            >
                              <Globe className="size-3 text-cyan" />
                              <span>{alert.ip_address}</span>
                            </button>
                          )}
                          {alert.camera_id && (
                            <button
                              type="button"
                              onClick={() => onSelectEntity?.("camera", alert.camera_id!)}
                              className="inline-flex items-center gap-1 rounded bg-muted/50 px-1.5 py-0.5 text-[11px] font-mono text-warning hover:border hover:border-warning"
                              title="Inspect camera cyber health"
                            >
                              <Camera className="size-3 text-warning" />
                              <span>{alert.camera_id}</span>
                            </button>
                          )}
                          {!alert.user_id && !alert.ip_address && !alert.camera_id && (
                            <span className="text-muted-foreground italic font-mono text-[10px]">{alert.entity_id}</span>
                          )}
                        </div>
                      </td>

                      {/* Confidence */}
                      <td className="whitespace-nowrap px-3 py-3 align-top">
                        <div className="flex flex-col gap-1">
                          <span className="font-mono text-xs font-semibold tabular-nums text-foreground">
                            {Math.round(alert.confidence * 100)}%
                          </span>
                          <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
                            <div
                              className={cn(
                                "h-full rounded-full",
                                alert.confidence >= 0.9 ? "bg-critical" : alert.confidence >= 0.75 ? "bg-warning" : "bg-cyan"
                              )}
                              style={{ width: `${Math.round(alert.confidence * 100)}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Status */}
                      <td className="whitespace-nowrap px-3 py-3 align-top">
                        <span
                          className={cn(
                            "inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium capitalize",
                            alert.status === "open" && "border border-critical/40 bg-critical/15 text-critical",
                            alert.status === "acknowledged" && "border border-warning/40 bg-warning/15 text-warning",
                            alert.status === "resolved" && "border border-success/40 bg-success/15 text-success"
                          )}
                        >
                          {alert.status === "open" && <span className="size-1.5 animate-pulse rounded-full bg-critical" />}
                          {alert.status === "acknowledged" && <Clock className="size-3" />}
                          {alert.status === "resolved" && <CheckCircle2 className="size-3" />}
                          {alert.status}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="whitespace-nowrap px-3 py-3 text-right align-top">
                        <div className="flex items-center justify-end gap-1.5">
                          {alert.status === "open" && (
                            <button
                              type="button"
                              disabled={isUpdating}
                              onClick={() => handleStatusChange(alert.id, "acknowledged")}
                              className="rounded border border-warning/40 bg-warning/10 px-2 py-1 text-[11px] font-medium text-warning transition-colors hover:bg-warning hover:text-black disabled:opacity-50"
                            >
                              Acknowledge
                            </button>
                          )}
                          {alert.status !== "resolved" && (
                            <button
                              type="button"
                              disabled={isUpdating}
                              onClick={() => handleStatusChange(alert.id, "resolved")}
                              className="rounded border border-success/40 bg-success/10 px-2 py-1 text-[11px] font-medium text-success transition-colors hover:bg-success hover:text-white disabled:opacity-50"
                            >
                              Resolve
                            </button>
                          )}
                          {alert.status === "resolved" && (
                            <button
                              type="button"
                              disabled={isUpdating}
                              onClick={() => handleStatusChange(alert.id, "open")}
                              className="rounded border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground transition-colors hover:border-critical hover:text-critical disabled:opacity-50"
                            >
                              Reopen
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
