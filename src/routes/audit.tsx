import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Download, Search } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel } from "@/components/vms/ui";
import { auditLogs } from "@/lib/mock-data";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/audit")({
  head: pageHead("Audit Logs", "Searchable record of operator actions, IP addresses and outcomes with CSV export."),
  component: Audit,
});

const users: string[] = ["All", ...Array.from(new Set(auditLogs.map((l) => l.user)))];

function Audit() {
  const [q, setQ] = useState("");
  const [user, setUser] = useState("All");
  const [result, setResult] = useState("All");
  const rows = useMemo(() => auditLogs.filter((l) =>
    (user === "All" || l.user === user) && (result === "All" || l.result === result) &&
    `${l.action} ${l.ip} ${l.user}`.toLowerCase().includes(q.toLowerCase())), [q, user, result]);

  const exportCsv = () => {
    const csv = ["timestamp,user,action,ip,result", ...rows.map((r) => [r.time, r.user, `"${r.action}"`, r.ip, r.result].join(","))].join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = "audit-logs-demo.csv"; a.click(); URL.revokeObjectURL(a.href);
    toast.success(`Exported ${rows.length} rows`);
  };

  return (
    <>
      <PageHeader title="Audit Logs" subtitle={`${rows.length} entries`} actions={<Button variant="secondary" onClick={exportCsv}><Download className="size-4" /> Export CSV</Button>} />
      <Panel>
        <div className="mb-4 flex flex-wrap gap-3">
          <div className="relative min-w-60 flex-1"><Search className="absolute left-3 top-2.5 size-4 text-muted-foreground" /><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search action, IP, user…" className="pl-9" /></div>
          <Select value={user} onValueChange={setUser}><SelectTrigger className="w-36"><SelectValue /></SelectTrigger><SelectContent>{users.map((u) => <SelectItem key={u} value={u}>{u === "All" ? "All users" : u}</SelectItem>)}</SelectContent></Select>
          <Select value={result} onValueChange={setResult}><SelectTrigger className="w-36"><SelectValue /></SelectTrigger><SelectContent>{["All", "Success", "Failure"].map((u) => <SelectItem key={u} value={u}>{u === "All" ? "All results" : u}</SelectItem>)}</SelectContent></Select>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground"><tr className="border-b">{["Timestamp", "User", "Action", "IP Address", "Result"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
            <tbody>{rows.map((l, i) => (
              <tr key={i} className="border-b border-border/50">
                <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{l.time}</td><td className="px-3 py-2.5">{l.user}</td><td className="px-3 py-2.5">{l.action}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-cyan">{l.ip}</td>
                <td className="px-3 py-2.5 text-xs"><span className={l.result === "Success" ? "text-success" : "text-critical"}>{l.result}</span></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </Panel>
    </>
  );
}
