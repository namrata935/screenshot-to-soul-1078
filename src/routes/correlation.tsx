import { createFileRoute } from "@tanstack/react-router";
import { Cctv, ShieldAlert, X } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from "recharts";
import { PageHeader, Panel, SeverityBadge, tooltipStyle, axisProps } from "@/components/vms/ui";
import { correlationPairs, correlatedRisk, riskLevel, riskProgression, CORRELATION_MULTIPLIER, CORRELATION_WINDOW_SECONDS } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/correlation")({
  head: pageHead("Threat Correlation", "Physical and cyber events correlated within a 60-second window with a 1.5x risk multiplier."),
  component: Correlation,
});

const bands = [
  { label: "Low", range: "< 35", cls: "border-success/40 text-success" },
  { label: "Medium", range: "35 – 69", cls: "border-warning/40 text-warning" },
  { label: "High", range: "70 – 99", cls: "border-critical/40 text-critical" },
  { label: "Critical", range: "100+", cls: "border-critical bg-critical/15 text-critical" },
];

function Correlation() {
  return (
    <>
      <PageHeader title="Threat Correlation" subtitle={`Events within ${CORRELATION_WINDOW_SECONDS}s are fused and multiplied ×${CORRELATION_MULTIPLIER}`} />
      <div className="grid gap-4 lg:grid-cols-5">
        <div className="panel glow-primary flex flex-col items-center justify-center p-6 lg:col-span-1">
          <p className="text-xs uppercase tracking-wider text-muted-foreground">Multiplier</p>
          <p className="text-5xl font-bold text-primary">×{CORRELATION_MULTIPLIER}</p>
          <p className="mt-1 text-xs text-muted-foreground">within {CORRELATION_WINDOW_SECONDS}s window</p>
        </div>
        {bands.map((b) => (
          <div key={b.label} className={cn("panel flex flex-col justify-center p-4", b.cls)}>
            <p className="text-sm font-semibold">{b.label}</p><p className="font-mono text-2xl">{b.range}</p>
          </div>
        ))}
      </div>

      <Panel title="Risk progression · COR-118" className="mt-4">
        <div className="h-64"><ResponsiveContainer><AreaChart data={riskProgression}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="t" {...axisProps} /><YAxis {...axisProps} domain={[0, 150]} /><Tooltip contentStyle={tooltipStyle} />
          <ReferenceLine y={35} stroke="var(--warning)" strokeDasharray="4 4" /><ReferenceLine y={70} stroke="var(--chart-3)" strokeDasharray="4 4" /><ReferenceLine y={100} stroke="var(--critical)" strokeDasharray="4 4" label={{ value: "Critical", fill: "var(--critical)", fontSize: 11 }} />
          <Area type="stepAfter" dataKey="risk" stroke="var(--critical)" fill="var(--critical)" fillOpacity={0.2} />
        </AreaChart></ResponsiveContainer></div>
      </Panel>

      <Panel title="Correlation timeline" className="mt-4">
        <div className="space-y-3">
          {correlationPairs.map((c) => {
            const inWindow = c.delta <= CORRELATION_WINDOW_SECONDS;
            const total = correlatedRisk(c.physical.score, c.cyber.score, c.delta);
            return (
              <div key={c.id} className={cn("rounded-lg border p-4", inWindow ? "border-primary/40 bg-primary/5" : "opacity-70")}>
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-sm text-cyan">{c.id}</span>
                  <span className="text-xs text-muted-foreground">Δt = {c.delta}s · {inWindow ? "CORRELATED" : "outside window"}</span>
                </div>
                <div className="grid items-center gap-3 md:grid-cols-[1fr_auto_1fr_auto]">
                  <div className="flex items-center gap-3 rounded-md border bg-panel p-3"><Cctv className="size-5 text-primary" /><div className="text-sm"><p>{c.physical.event}</p><p className="font-mono text-xs text-muted-foreground">{c.physical.cam} · {c.physical.t} · score {c.physical.score}</p></div></div>
                  <span className="text-center font-mono text-xs text-muted-foreground">+</span>
                  <div className="flex items-center gap-3 rounded-md border bg-panel p-3"><ShieldAlert className="size-5 text-cyan" /><div className="text-sm"><p>{c.cyber.event}</p><p className="font-mono text-xs text-muted-foreground">{c.cyber.ip} · {c.cyber.t} · score {c.cyber.score}</p></div></div>
                  <div className="flex items-center gap-2 md:justify-end">
                    {inWindow && <span className="flex items-center font-mono text-xs text-primary"><X className="size-3" />{CORRELATION_MULTIPLIER}</span>}
                    <span className="font-mono text-xl font-semibold">{total}</span>
                    <SeverityBadge severity={riskLevel(total)} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </>
  );
}
