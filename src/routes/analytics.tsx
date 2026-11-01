import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { PageHeader, Panel, tooltipStyle, axisProps } from "@/components/vms/ui";
import { trends, severityDist, cameraStats } from "@/lib/mock-data";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/analytics")({
  head: pageHead("Analytics", "Incident trends, severity distribution and risk progression across cameras."),
  component: Analytics,
});

const sevColors = ["var(--success)", "var(--warning)", "var(--chart-3)", "var(--critical)"];

function Analytics() {
  const [range, setRange] = useState<keyof typeof trends>("weekly");
  const data = trends[range];
  return (
    <>
      <PageHeader title="Analytics" subtitle="Trends across physical and cyber domains"
        actions={<Tabs value={range} onValueChange={(v) => setRange(v as keyof typeof trends)}><TabsList><TabsTrigger value="daily">Daily</TabsTrigger><TabsTrigger value="weekly">Weekly</TabsTrigger><TabsTrigger value="monthly">Monthly</TabsTrigger></TabsList></Tabs>} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Incident trend">
          <div className="h-64"><ResponsiveContainer><LineChart data={data}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="label" {...axisProps} /><YAxis {...axisProps} /><Tooltip contentStyle={tooltipStyle} />
            <Line dataKey="incidents" stroke="var(--chart-1)" strokeWidth={2} dot={false} />
          </LineChart></ResponsiveContainer></div>
        </Panel>
        <Panel title="Physical vs Cyber">
          <div className="h-64"><ResponsiveContainer><BarChart data={data}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="label" {...axisProps} /><YAxis {...axisProps} /><Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--accent)" }} /><Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="physical" fill="var(--chart-1)" radius={[3, 3, 0, 0]} /><Bar dataKey="cyber" fill="var(--chart-2)" radius={[3, 3, 0, 0]} />
          </BarChart></ResponsiveContainer></div>
        </Panel>
        <Panel title="Risk progression">
          <div className="h-64"><ResponsiveContainer><LineChart data={data}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="label" {...axisProps} /><YAxis {...axisProps} /><Tooltip contentStyle={tooltipStyle} />
            <Line dataKey="risk" stroke="var(--warning)" strokeWidth={2} />
          </LineChart></ResponsiveContainer></div>
        </Panel>
        <Panel title="Severity distribution">
          <div className="h-64"><ResponsiveContainer><PieChart>
            <Pie data={severityDist} dataKey="value" innerRadius={55} outerRadius={85} stroke="none" paddingAngle={3}>{severityDist.map((_, i) => <Cell key={i} fill={sevColors[i]} />)}</Pie>
            <Tooltip contentStyle={tooltipStyle} /><Legend wrapperStyle={{ fontSize: 12 }} />
          </PieChart></ResponsiveContainer></div>
        </Panel>
        <Panel title="Camera-wise events" className="lg:col-span-2">
          <div className="h-64"><ResponsiveContainer><BarChart data={cameraStats}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="camera" {...axisProps} /><YAxis {...axisProps} /><Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--accent)" }} />
            <Bar dataKey="events" fill="var(--cyan)" radius={[3, 3, 0, 0]} />
          </BarChart></ResponsiveContainer></div>
        </Panel>
      </div>
    </>
  );
}
