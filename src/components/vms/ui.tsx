import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/mock-data";

export function DemoBadge() {
  return (
    <span className="rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-widest text-warning">
      DEMO DATA
    </span>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <DemoBadge />
        </div>
        {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

const sevStyles: Record<Severity, string> = {
  Low: "bg-success/15 text-success border-success/30",
  Medium: "bg-warning/15 text-warning border-warning/30",
  High: "bg-critical/15 text-critical border-critical/30",
  Critical: "bg-critical text-destructive-foreground border-critical glow-critical",
};
export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={cn("inline-flex rounded border px-2 py-0.5 text-xs font-medium", sevStyles[severity])}>{severity}</span>;
}

export function StatusDot({ tone }: { tone: "success" | "warning" | "critical" | "muted" }) {
  const c = { success: "bg-success", warning: "bg-warning", critical: "bg-critical", muted: "bg-muted-foreground" }[tone];
  return <span className={cn("inline-block size-2 rounded-full", c, tone !== "muted" && "animate-pulse")} />;
}

export function KpiCard({ label, value, icon: Icon, tone = "primary", hint }: {
  label: string; value: ReactNode; icon: LucideIcon; tone?: "primary" | "cyan" | "critical" | "warning" | "success"; hint?: string;
}) {
  const t = { primary: "text-primary bg-primary/10", cyan: "text-cyan bg-cyan/10", critical: "text-critical bg-critical/10", warning: "text-warning bg-warning/10", success: "text-success bg-success/10" }[tone];
  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
        <span className={cn("rounded-md p-1.5", t)}><Icon className="size-4" /></span>
      </div>
      <p className="mt-3 text-2xl font-semibold tabular-nums">{value}</p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function Panel({ title, children, className, action }: { title?: string; children: ReactNode; className?: string; action?: ReactNode }) {
  return (
    <section className={cn("panel p-4", className)}>
      {title && (
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function VideoPlaceholder({ label, offline }: { label: string; offline?: boolean }) {
  return (
    <div className={cn("grid-bg relative flex aspect-video items-center justify-center rounded-md border bg-terminal", !offline && "scanline")}>
      <span className="font-mono text-xs text-muted-foreground">{offline ? "NO SIGNAL" : label}</span>
      {!offline && (
        <span className="absolute left-2 top-2 flex items-center gap-1 rounded bg-critical/90 px-1.5 py-0.5 font-mono text-[10px] text-destructive-foreground">
          ● REC
        </span>
      )}
    </div>
  );
}

export const chartColors = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)"];
export const tooltipStyle = { background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--foreground)", fontSize: 12 };
export const axisProps = { stroke: "var(--muted-foreground)", fontSize: 11, tickLine: false, axisLine: false } as const;
