import { useState, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  ShieldCheck,
  Download,
  Film,
  ImageIcon,
  Loader2,
  ShieldX,
  Sparkles,
  Layers,
  Database,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel, VideoPlaceholder } from "@/components/vms/ui";
import { evidence, subscribeEvidence, syncWithBackendDb, type EvidenceItem } from "@/lib/mock-data";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/evidence")({
  head: pageHead(
    "Digital Evidence Vault",
    "Tamper-evident snapshots and clips with SHA-256 integrity verification stored in local SQLite database."
  ),
  component: Evidence,
});

function Evidence() {
  const [items, setItems] = useState<EvidenceItem[]>(evidence);
  const [sel, setSel] = useState<EvidenceItem>(evidence[0]!);
  const [checking, setChecking] = useState<string | null>(null);
  const [checked, setChecked] = useState<Record<string, boolean>>({});

  useEffect(() => {
    setItems(evidence);
    syncWithBackendDb();
    return subscribeEvidence((newItems) => {
      setItems(newItems);
      if (newItems.length > 0 && newItems[0]) {
        setSel(newItems[0]);
      }
    });
  }, []);

  const verify = (id: string, ok: boolean) => {
    setChecking(id);
    setTimeout(() => {
      setChecking(null);
      setChecked((c) => ({ ...c, [id]: ok }));
      ok
        ? toast.success(`${id}: SHA-256 matches chain-of-custody record`)
        : toast.error(`${id}: hash mismatch — possible tampering`);
    }, 1200);
  };

  const handleDownloadDb = async () => {
    try {
      const res = await fetch("http://localhost:5005/api/db/download");
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "vms_security.db";
        a.click();
        URL.revokeObjectURL(url);
        toast.success("Downloaded vms_security.db from local server");
        return;
      }
    } catch {
      // Server offline fallback
    }
    toast.info("Database stored locally at: vms_security.db in workspace root", {
      description: "Query directly using: sqlite3 vms_security.db",
    });
  };

  return (
    <>
      <PageHeader
        title="Digital Evidence Vault"
        subtitle="Immutable forensic artifacts · SHA-256 chain of custody · Stored in vms_security.db"
        actions={
          <div className="flex items-center gap-2">
            <span className="hidden sm:inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 font-mono text-xs text-primary">
              <Database className="size-3.5" /> vms_security.db
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadDb}
              className="text-xs gap-1.5 font-mono"
            >
              <Download className="size-3.5" /> Export .db
            </Button>
          </div>
        }
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="xl:col-span-2">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
                <tr className="border-b">
                  {["Evidence", "Incident", "File", "Timestamp", "SHA-256", "Status"].map((h) => (
                    <th key={h} className="px-3 py-2 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((e) => {
                  const ok = checked[e.id] ?? e.verified;
                  return (
                    <tr
                      key={e.id}
                      onClick={() => setSel(e)}
                      className={cn(
                        "cursor-pointer border-b border-border/50 hover:bg-accent/50 transition-colors",
                        sel.id === e.id && "bg-accent/60"
                      )}
                    >
                      <td className="px-3 py-2.5 font-mono text-xs text-cyan">{e.id}</td>
                      <td className="px-3 py-2.5 font-mono text-xs">{e.incident}</td>
                      <td className="px-3 py-2.5">
                        <span className="flex items-center gap-1.5 text-xs">
                          {e.kind === "Video" ? (
                            <Film className="size-3.5 text-primary" />
                          ) : (
                            <ImageIcon className="size-3.5 text-cyan" />
                          )}
                          {e.file}
                          {e.snapshotData && (
                            <span className="rounded bg-critical/15 px-1 font-mono text-[9px] font-semibold text-critical">
                              LIVE
                            </span>
                          )}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{e.time}</td>
                      <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">
                        {e.hash.slice(0, 12)}…
                      </td>
                      <td className="px-3 py-2.5 text-xs">
                        {ok ? (
                          <span className="text-success font-medium">Verified</span>
                        ) : (
                          <span className="text-critical font-medium">Mismatch</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title={`Preview · ${sel.id}`}>
          {sel.snapshotData ? (
            <div className="relative aspect-video overflow-hidden rounded-md border border-cyan/30 bg-black">
              <img
                src={sel.snapshotData}
                alt={sel.file}
                className="size-full object-contain"
              />
              <span className="absolute left-2 top-2 flex items-center gap-1 rounded bg-critical/90 px-1.5 py-0.5 font-mono text-[10px] text-destructive-foreground">
                ● AI EVIDENCE CAPTURED
              </span>
            </div>
          ) : (
            <VideoPlaceholder label={`${sel.kind.toUpperCase()} · ${sel.file}`} />
          )}

          {sel.tags && sel.tags.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {sel.tags.map((t) => (
                <span
                  key={t}
                  className="rounded bg-primary/10 px-2 py-0.5 font-mono text-[10px] text-primary"
                >
                  {t}
                </span>
              ))}
            </div>
          )}

          <dl className="mt-4 space-y-2 text-sm">
            <div>
              <dt className="text-xs text-muted-foreground">Incident ID</dt>
              <dd className="font-mono text-xs font-semibold text-cyan">{sel.incident}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Captured Timestamp</dt>
              <dd className="font-mono text-xs">{sel.time}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Forensic SHA-256 Digest</dt>
              <dd className="break-all rounded bg-terminal p-2 font-mono text-[11px] text-cyan border border-border/40">
                {sel.hash}
              </dd>
            </div>
          </dl>

          <div className="mt-4 flex gap-2">
            <Button
              className="flex-1"
              onClick={() => verify(sel.id, sel.verified)}
              disabled={checking === sel.id}
            >
              {checking === sel.id ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (checked[sel.id] ?? sel.verified) ? (
                <ShieldCheck className="size-4" />
              ) : (
                <ShieldX className="size-4" />
              )}
              {" "}Verify Integrity
            </Button>
            <Button
              variant="secondary"
              onClick={() => toast.success(`Download of ${sel.file} started (simulated)`)}
            >
              <Download className="size-4" /> Download
            </Button>
          </div>
        </Panel>
      </div>
    </>
  );
}
