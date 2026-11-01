import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRound, Webhook, Activity, Radar, CameraOff } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { KpiCard, PageHeader, Panel, SeverityBadge, tooltipStyle, axisProps } from "@/components/vms/ui";
import { cyberKpis, cyberEvents, terminalLines, hourly } from "@/lib/mock-data";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/cyber")({
  head: pageHead("Cybersecurity Monitor", "Failed logins, unauthorized API calls, port scans and camera compromise events."),
  component: Cyber,
});

const icons = [KeyRound, Webhook, Activity, Radar, CameraOff];
const tones = ["warning", "cyan", "primary", "warning", "critical"] as const;

function Cyber() {
  const [lines, setLines] = useState(() => terminalLines.slice(0, 5).map((l, i) => ({ id: i, l })));
  useEffect(() => {
    let n = 5;
    const t = setInterval(() => {
      const ts = new Date().toISOString().slice(11, 19);
      setLines((p) => [...p.slice(-13), { id: n, l: `${ts} ${terminalLines[n % terminalLines.length]}` }]);
      n++;
    }, 1800);
    return () => clearInterval(t);
  }, []);

  return (
    <>
      <PageHeader title="Cybersecurity Monitor" subtitle="Network, identity and device threat telemetry" />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        {cyberKpis.map((k, i) => <KpiCard key={k.label} label={k.label} value={k.value.toLocaleString()} icon={icons[i] ?? Activity} tone={tones[i] ?? "primary"} hint={`${k.delta} vs yesterday`} />)}
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel title="Live event feed">
          <div className="h-72 overflow-hidden rounded-md border bg-terminal p-3 font-mono text-xs leading-6">
            {lines.map(({ id, l }) => (
              <p key={id} className={l.includes("[CORR]") || l.includes("DROP") ? "text-critical" : l.includes("[AUTH]") ? "text-warning" : "text-success"}>
                <span className="text-muted-foreground">$ </span>{l}
              </p>
            ))}
            <p className="animate-pulse text-cyan">▋</p>
          </div>
        </Panel>
        <Panel title="Cyber activity (24h)">
          <div className="h-72"><ResponsiveContainer><AreaChart data={hourly}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="t" {...axisProps} /><YAxis {...axisProps} /><Tooltip contentStyle={tooltipStyle} />
            <Area dataKey="cyber" stroke="var(--cyan)" fill="var(--cyan)" fillOpacity={0.2} />
          </AreaChart></ResponsiveContainer></div>
        </Panel>
      </div>
      <Panel title="Threat events" className="mt-4">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground"><tr className="border-b">{["Time", "Event", "Source IP", "Severity", "Status"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
            <tbody>{cyberEvents.map((e, i) => (
              <tr key={i} className="border-b border-border/50">
                <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{e.time}</td><td className="px-3 py-2.5">{e.event}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-cyan">{e.ip}</td><td className="px-3 py-2.5"><SeverityBadge severity={e.severity} /></td>
                <td className="px-3 py-2.5 text-xs">{e.status}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </Panel>
    </>
  );
}
