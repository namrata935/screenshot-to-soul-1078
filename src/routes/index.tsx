import { createFileRoute, Link } from "@tanstack/react-router";
import { Cctv, Siren, Flame, ShieldAlert, Footprints, Gauge } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, AreaChart, Area, XAxis, YAxis, CartesianGrid, Legend } from "recharts";
import { KpiCard, PageHeader, Panel, SeverityBadge, VideoPlaceholder, StatusDot, chartColors, tooltipStyle, axisProps } from "@/components/vms/ui";
import { cameras, incidents, threatDistribution, hourly } from "@/lib/mock-data";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/")({
  head: pageHead("Overview", "Real-time overview of cameras, incidents, cyber events and system risk."),
  component: Overview,
});

const health = [
  { name: "Video ingest", v: 98, tone: "success" as const },
  { name: "AI inference nodes", v: 91, tone: "success" as const },
  { name: "SIEM connector", v: 76, tone: "warning" as const },
  { name: "Evidence storage", v: 64, tone: "warning" as const },
];

function Overview() {
  const open = incidents.filter((i) => i.status !== "Resolved");
  return (
    <>
      <PageHeader title="Command Overview" subtitle="Unified physical and cyber situational awareness" />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <KpiCard label="Total Cameras" value={cameras.length * 16} icon={Cctv} hint={`${cameras.filter((c) => c.online).length * 16} online`} />
        <KpiCard label="Active Incidents" value={open.length} icon={Siren} tone="warning" />
        <KpiCard label="Critical Threats" value={incidents.filter((i) => i.severity === "Critical").length} icon={Flame} tone="critical" />
        <KpiCard label="Cyber Events" value="1,749" icon={ShieldAlert} tone="cyan" hint="last 24h" />
        <KpiCard label="Physical Events" value="312" icon={Footprints} hint="last 24h" />
        <KpiCard label="Risk Score" value={<span className="text-warning">72</span>} icon={Gauge} tone="warning" hint="High" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel title="Physical vs Cyber activity (24h)" className="xl:col-span-2">
          <div className="h-64">
            <ResponsiveContainer>
              <AreaChart data={hourly}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" {...axisProps} /><YAxis {...axisProps} />
                <Tooltip contentStyle={tooltipStyle} /><Legend wrapperStyle={{ fontSize: 12 }} />
                <Area dataKey="physical" stroke="var(--chart-1)" fill="var(--chart-1)" fillOpacity={0.2} />
                <Area dataKey="cyber" stroke="var(--chart-2)" fill="var(--chart-2)" fillOpacity={0.2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Threat distribution">
          <div className="h-64">
            <ResponsiveContainer>
              <PieChart>
                <Pie data={threatDistribution} dataKey="value" innerRadius={55} outerRadius={85} paddingAngle={3} stroke="none">
                  {threatDistribution.map((_, i) => <Cell key={i} fill={chartColors[i]} />)}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} /><Legend wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel title="Recent incidents" className="xl:col-span-2" action={<Link to="/incidents" className="text-xs text-primary hover:underline">View all</Link>}>
          <ul className="divide-y">
            {incidents.slice(0, 6).map((i) => (
              <li key={i.id} className="flex items-center gap-3 py-2.5 text-sm">
                <span className="w-20 font-mono text-xs text-muted-foreground">{i.id}</span>
                <span className="flex-1 truncate">{i.type}</span>
                <span className="hidden w-48 truncate text-xs text-muted-foreground md:block">{i.source}</span>
                <SeverityBadge severity={i.severity} />
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="System health">
          <ul className="space-y-4">
            {health.map((h) => (
              <li key={h.name}>
                <div className="mb-1 flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2"><StatusDot tone={h.tone} />{h.name}</span>
                  <span className="font-mono text-xs">{h.v}%</span>
                </div>
                <div className="h-1.5 rounded bg-muted"><div className={h.tone === "success" ? "h-full rounded bg-success" : "h-full rounded bg-warning"} style={{ width: `${h.v}%` }} /></div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <Panel title="Camera previews" className="mt-4" action={<Link to="/cameras" className="text-xs text-primary hover:underline">Manage</Link>}>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {cameras.slice(0, 4).map((c) => (
            <div key={c.id}>
              <VideoPlaceholder label={c.id} offline={!c.online} />
              <p className="mt-1.5 text-xs"><span className="font-medium">{c.name}</span> <span className="text-muted-foreground">· {c.location}</span></p>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}
