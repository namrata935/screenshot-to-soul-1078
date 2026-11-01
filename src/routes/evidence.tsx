import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { ShieldCheck, Download, Film, ImageIcon, Loader2, ShieldX } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel, VideoPlaceholder } from "@/components/vms/ui";
import { evidence } from "@/lib/mock-data";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/evidence")({
  head: pageHead("Digital Evidence Vault", "Tamper-evident snapshots and clips with SHA-256 integrity verification."),
  component: Evidence,
});

function Evidence() {
  const [sel, setSel] = useState(evidence[0]!);
  const [checking, setChecking] = useState<string | null>(null);
  const [checked, setChecked] = useState<Record<string, boolean>>({});

  const verify = (id: string, ok: boolean) => {
    setChecking(id);
    setTimeout(() => {
      setChecking(null); setChecked((c) => ({ ...c, [id]: ok }));
      ok ? toast.success(`${id}: SHA-256 matches chain-of-custody record`) : toast.error(`${id}: hash mismatch — possible tampering`);
    }, 1200);
  };

  return (
    <>
      <PageHeader title="Digital Evidence Vault" subtitle="Immutable forensic artifacts · SHA-256 chain of custody" />
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="xl:col-span-2">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground"><tr className="border-b">{["Evidence", "Incident", "File", "Timestamp", "SHA-256", "Status"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
              <tbody>{evidence.map((e) => {
                const ok = checked[e.id] ?? e.verified;
                return (
                  <tr key={e.id} onClick={() => setSel(e)} className={cn("cursor-pointer border-b border-border/50 hover:bg-accent/50", sel.id === e.id && "bg-accent/60")}>
                    <td className="px-3 py-2.5 font-mono text-xs text-cyan">{e.id}</td>
                    <td className="px-3 py-2.5 font-mono text-xs">{e.incident}</td>
                    <td className="px-3 py-2.5"><span className="flex items-center gap-1.5 text-xs">{e.kind === "Video" ? <Film className="size-3.5" /> : <ImageIcon className="size-3.5" />}{e.file}</span></td>
                    <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{e.time}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{e.hash.slice(0, 12)}…</td>
                    <td className="px-3 py-2.5 text-xs">{ok ? <span className="text-success">Verified</span> : <span className="text-critical">Mismatch</span>}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
        </Panel>
        <Panel title={`Preview · ${sel.id}`}>
          <VideoPlaceholder label={`${sel.kind.toUpperCase()} · ${sel.file}`} />
          <dl className="mt-4 space-y-2 text-sm">
            <div><dt className="text-xs text-muted-foreground">Incident</dt><dd className="font-mono">{sel.incident}</dd></div>
            <div><dt className="text-xs text-muted-foreground">Captured</dt><dd className="font-mono text-xs">{sel.time}</dd></div>
            <div><dt className="text-xs text-muted-foreground">SHA-256</dt><dd className="break-all rounded bg-terminal p-2 font-mono text-[11px] text-cyan">{sel.hash}</dd></div>
          </dl>
          <div className="mt-4 flex gap-2">
            <Button className="flex-1" onClick={() => verify(sel.id, sel.verified)} disabled={checking === sel.id}>
              {checking === sel.id ? <Loader2 className="size-4 animate-spin" /> : (checked[sel.id] ?? sel.verified) ? <ShieldCheck className="size-4" /> : <ShieldX className="size-4" />} Verify Integrity
            </Button>
            <Button variant="secondary" onClick={() => toast.success(`Download of ${sel.file} started (simulated)`)}><Download className="size-4" /> Download</Button>
          </div>
        </Panel>
      </div>
    </>
  );
}
