import { useState } from "react";
import {
  Cctv,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CameraOff,
  Radio,
  Clock,
  Filter,
  Search,
  ExternalLink,
  Lock,
  Unlock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { type CameraCyberHealth } from "@/lib/cyber-api";
import { StatusDot } from "./ui";

interface CameraCyberHealthProps {
  cameras: CameraCyberHealth[];
  isLoading?: boolean;
  onSelectCameraAlerts?: (cameraId: string) => void;
  onSelectCameraInGraph?: (cameraId: string) => void;
}

export function CameraCyberHealthView({
  cameras,
  isLoading = false,
  onSelectCameraAlerts,
  onSelectCameraInGraph,
}: CameraCyberHealthProps) {
  const [filter, setFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const healthyCount = cameras.filter((c) => c.status === "healthy").length;
  const warningCount = cameras.filter((c) => c.status === "warning").length;
  const tamperedCount = cameras.filter((c) => c.status === "tampered").length;
  const offlineCount = cameras.filter((c) => c.status === "offline").length;

  const filteredCameras = cameras.filter((c) => {
    if (filter !== "all" && c.status !== filter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        c.camera_id.toLowerCase().includes(q) ||
        c.name.toLowerCase().includes(q) ||
        c.location.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* KPI Overview row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Healthy Heartbeats</span>
            <ShieldCheck className="size-4 text-success" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-success">{healthyCount}</p>
          <p className="text-[10px] text-muted-foreground">Pinging within 30s threshold</p>
        </div>

        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Jitter / Warnings</span>
            <AlertTriangle className="size-4 text-warning" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-warning">{warningCount}</p>
          <p className="text-[10px] text-muted-foreground">High latency or failed RTSP probes</p>
        </div>

        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Tamper Suspected</span>
            <ShieldAlert className="size-4 text-critical" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-critical">{tamperedCount}</p>
          <p className="text-[10px] text-critical">Missing heartbeats or hash mismatch</p>
        </div>

        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Offline / Disconnected</span>
            <CameraOff className="size-4 text-muted-foreground" />
          </div>
          <p className="mt-2 text-2xl font-bold tabular-nums text-muted-foreground">{offlineCount}</p>
          <p className="text-[10px] text-muted-foreground">No active network response</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 rounded-lg border border-border/70 bg-card p-3 md:flex-row md:items-center md:justify-between">
        <div className="inline-flex rounded-md border border-border/80 bg-background/50 p-0.5 text-xs">
          <button
            type="button"
            onClick={() => setFilter("all")}
            className={cn(
              "rounded px-2.5 py-1 font-medium transition-colors",
              filter === "all" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"
            )}
          >
            All Cameras ({cameras.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("healthy")}
            className={cn(
              "rounded px-2.5 py-1 font-medium transition-colors",
              filter === "healthy" ? "bg-success text-white" : "text-success hover:bg-success/10"
            )}
          >
            Healthy ({healthyCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter("warning")}
            className={cn(
              "rounded px-2.5 py-1 font-medium transition-colors",
              filter === "warning" ? "bg-warning text-black font-semibold" : "text-warning hover:bg-warning/10"
            )}
          >
            Warnings ({warningCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter("tampered")}
            className={cn(
              "rounded px-2.5 py-1 font-medium transition-colors",
              filter === "tampered" ? "bg-critical text-destructive-foreground" : "text-critical hover:bg-critical/10"
            )}
          >
            Tampered ({tamperedCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter("offline")}
            className={cn(
              "rounded px-2.5 py-1 font-medium transition-colors",
              filter === "offline" ? "bg-muted text-foreground" : "text-muted-foreground hover:bg-muted/40"
            )}
          >
            Offline ({offlineCount})
          </button>
        </div>

        <div className="relative md:w-64">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search camera ID or name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border border-border bg-background py-1 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
          />
        </div>
      </div>

      {/* Camera Cyber Table */}
      <div className="overflow-hidden rounded-lg border border-border bg-card">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border bg-muted/30 uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2.5 font-medium">Camera</th>
                <th className="px-3 py-2.5 font-medium">Heartbeat Status</th>
                <th className="px-3 py-2.5 font-medium">Security Posture</th>
                <th className="px-3 py-2.5 font-medium">RTSP Security</th>
                <th className="px-3 py-2.5 font-medium">Unauth. Probes</th>
                <th className="px-3 py-2.5 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {filteredCameras.map((cam) => {
                const isTampered = cam.status === "tampered";
                const isWarning = cam.status === "warning";
                const isOffline = cam.status === "offline";
                const isHealthy = cam.status === "healthy";

                return (
                  <tr
                    key={cam.camera_id}
                    className={cn(
                      "transition-colors hover:bg-muted/20",
                      isTampered && "bg-critical/5"
                    )}
                  >
                    {/* Camera Name & ID */}
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={cn(
                            "rounded-md p-1.5",
                            isTampered
                              ? "bg-critical/15 text-critical"
                              : isWarning
                              ? "bg-warning/15 text-warning"
                              : isOffline
                              ? "bg-muted text-muted-foreground"
                              : "bg-success/15 text-success"
                          )}
                        >
                          <Cctv className="size-4" />
                        </span>
                        <div>
                          <div className="flex items-center gap-1.5 font-mono text-[11px] font-semibold text-foreground">
                            {cam.camera_id}
                            <span className="font-sans text-xs font-normal text-muted-foreground">· {cam.name}</span>
                          </div>
                          <p className="text-[10px] text-muted-foreground">{cam.location}</p>
                        </div>
                      </div>
                    </td>

                    {/* Heartbeat Status */}
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            "size-2 rounded-full",
                            isHealthy && "bg-success animate-pulse",
                            isWarning && "bg-warning animate-pulse",
                            isTampered && "bg-critical animate-ping",
                            isOffline && "bg-muted-foreground"
                          )}
                        />
                        <div className="font-mono text-[11px]">
                          <span
                            className={cn(
                              isHealthy && "text-success",
                              isWarning && "text-warning",
                              isTampered && "text-critical font-bold",
                              isOffline && "text-muted-foreground"
                            )}
                          >
                            {cam.heartbeat_age_seconds < 60
                              ? `${cam.heartbeat_age_seconds}s ago`
                              : `${Math.round(cam.heartbeat_age_seconds / 60)}m ago`}
                          </span>
                          {isTampered && (
                            <span className="ml-1.5 rounded bg-critical/20 px-1 py-0.5 text-[9px] text-critical">
                              TIMEOUT EXCEEDED
                            </span>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* Security Posture */}
                    <td className="px-3 py-3">
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase",
                          isHealthy && "border-success/30 bg-success/10 text-success",
                          isWarning && "border-warning/30 bg-warning/10 text-warning",
                          isTampered && "border-critical bg-critical/15 text-critical glow-critical",
                          isOffline && "border-border bg-muted text-muted-foreground"
                        )}
                      >
                        {isHealthy && "HEALTHY"}
                        {isWarning && "PROBE SPIKE"}
                        {isTampered && "TAMPER SUSPECTED"}
                        {isOffline && "OFFLINE"}
                      </span>
                    </td>

                    {/* RTSP Stream Security */}
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-1 font-mono text-[10px]">
                        {cam.stream_secure ? (
                          <span className="flex items-center gap-1 text-success">
                            <Lock className="size-3" /> TLS / SRTP
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-critical">
                            <Unlock className="size-3" /> EXPOSED (Port 554)
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Unauthorized attempts */}
                    <td className="px-3 py-3">
                      <span
                        className={cn(
                          "font-mono text-xs font-semibold tabular-nums",
                          cam.unauthorized_attempts > 5 ? "text-critical" : cam.unauthorized_attempts > 0 ? "text-warning" : "text-muted-foreground"
                        )}
                      >
                        {cam.unauthorized_attempts}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="px-3 py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {onSelectCameraAlerts && (
                          <button
                            type="button"
                            onClick={() => onSelectCameraAlerts(cam.camera_id)}
                            className="rounded border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground transition-colors hover:border-cyan hover:text-cyan"
                          >
                            Filter Alerts ({cam.active_alerts})
                          </button>
                        )}
                        {onSelectCameraInGraph && (
                          <button
                            type="button"
                            onClick={() => onSelectCameraInGraph(cam.camera_id)}
                            className="rounded border border-cyan/40 bg-cyan/10 px-2 py-1 text-[11px] font-medium text-cyan transition-colors hover:bg-cyan hover:text-black"
                          >
                            Graph View
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

