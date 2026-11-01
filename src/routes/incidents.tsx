import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Search } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel, SeverityBadge } from "@/components/vms/ui";
import { incidents as seed, type Incident, type EventKind } from "@/lib/mock-data";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/incidents")({
  head: pageHead("Live Incidents", "Searchable and filterable live feed of physical, cyber and correlated incidents."),
  component: Incidents,
});

const kinds: ("All" | EventKind)[] = ["All", "Physical", "Cyber", "Correlated"];

function Incidents() {
  const [data, setData] = useState(seed);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<(typeof kinds)[number]>("All");
  const [sev, setSev] = useState("All");
  const [sel, setSel] = useState<Incident | null>(null);

  const rows = useMemo(() => data.filter((i) =>
    (kind === "All" || i.kind === kind) && (sev === "All" || i.severity === sev) &&
    `${i.id} ${i.type} ${i.source}`.toLowerCase().includes(q.toLowerCase())), [data, q, kind, sev]);

  const update = (status: Incident["status"]) => {
    if (!sel) return;
    setData((d) => d.map((i) => (i.id === sel.id ? { ...i, status } : i)));
    setSel({ ...sel, status });
    toast.success(`${sel.id} marked ${status}`);
  };

  return (
    <>
      <PageHeader title="Live Incidents" subtitle={`${rows.length} incidents match current filters`} />
      <Panel>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative min-w-60 flex-1">
            <Search className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search ID, type, source…" className="pl-9" />
          </div>
          <div className="flex rounded-md border p-0.5">
            {kinds.map((k) => (
              <button key={k} onClick={() => setKind(k)} className={cn("rounded px-3 py-1.5 text-xs", kind === k ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground")}>{k}</button>
            ))}
          </div>
          <Select value={sev} onValueChange={setSev}>
            <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
            <SelectContent>{["All", "Low", "Medium", "High", "Critical"].map((s) => <SelectItem key={s} value={s}>{s === "All" ? "All severities" : s}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
              <tr className="border-b">{["ID", "Timestamp", "Event", "Type", "Source", "Severity", "Risk", "Status"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id} onClick={() => setSel(i)} className="cursor-pointer border-b border-border/50 hover:bg-accent/50">
                  <td className="px-3 py-2.5 font-mono text-xs text-cyan">{i.id}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{i.time}</td>
                  <td className="px-3 py-2.5">{i.type}</td>
                  <td className="px-3 py-2.5 text-xs">{i.kind}</td>
                  <td className="px-3 py-2.5 text-xs text-muted-foreground">{i.source}</td>
                  <td className="px-3 py-2.5"><SeverityBadge severity={i.severity} /></td>
                  <td className="px-3 py-2.5 font-mono">{i.risk}</td>
                  <td className="px-3 py-2.5 text-xs">{i.status}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={8} className="py-10 text-center text-muted-foreground">No incidents match.</td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>

      <Sheet open={!!sel} onOpenChange={(o) => !o && setSel(null)}>
        <SheetContent className="sm:max-w-md">
          {sel && (
            <>
              <SheetHeader>
                <SheetTitle className="font-mono">{sel.id}</SheetTitle>
                <SheetDescription>{sel.type}</SheetDescription>
              </SheetHeader>
              <div className="space-y-4 px-4">
                <dl className="grid grid-cols-2 gap-3 text-sm">
                  {[["Timestamp", sel.time], ["Type", sel.kind], ["Source", sel.source], ["Risk score", sel.risk], ["Status", sel.status]].map(([k, v]) => (
                    <div key={k as string}><dt className="text-xs text-muted-foreground">{k}</dt><dd className="font-medium">{v}</dd></div>
                  ))}
                  <div><dt className="text-xs text-muted-foreground">Severity</dt><dd><SeverityBadge severity={sel.severity} /></dd></div>
                </dl>
                <p className="rounded-md border bg-panel p-3 text-sm text-muted-foreground">{sel.description}</p>
                <div className="flex gap-2">
                  <Button className="flex-1" variant="secondary" onClick={() => update("Investigating")}>Investigate</Button>
                  <Button className="flex-1" onClick={() => update("Resolved")}>Resolve</Button>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
