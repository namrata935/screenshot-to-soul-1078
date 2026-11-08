import { useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Check,
  Loader2,
  ExternalLink,
  Lock,
  History,
  AlertTriangle,
  RotateCcw,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel, SeverityBadge } from "@/components/vms/ui";
import { incidents as seed, type Incident, type EventKind } from "@/lib/mock-data";
import { verifyIncidentIntegrity, computeIncidentHashSync } from "@/lib/incident-crypto";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/incidents")({
  head: pageHead(
    "Live Incidents",
    "Searchable and filterable live feed of physical, cyber and correlated incidents with SHA-256 chain-of-custody verification."
  ),
  component: Incidents,
});

const kinds: ("All" | EventKind)[] = ["All", "Physical", "Cyber", "Correlated"];
const integrityFilters = ["All", "Verified Only", "Tampered Only"] as const;

export function Incidents() {
  const [data, setData] = useState<Incident[]>(seed);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<(typeof kinds)[number]>("All");
  const [sev, setSev] = useState("All");
  const [integrityFilter, setIntegrityFilter] = useState<(typeof integrityFilters)[number]>("All");
  const [sel, setSel] = useState<Incident | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  const rows = useMemo(() => {
    return data.filter((i) => {
      const matchKind = kind === "All" || i.kind === kind;
      const matchSev = sev === "All" || i.severity === sev;
      const matchIntegrity =
        integrityFilter === "All"
          ? true
          : integrityFilter === "Tampered Only"
          ? i.tampered
          : !i.tampered;
      const matchQuery = `${i.id} ${i.type} ${i.source} ${i.hash}`
        .toLowerCase()
        .includes(q.toLowerCase());
      return matchKind && matchSev && matchIntegrity && matchQuery;
    });
  }, [data, q, kind, sev, integrityFilter]);

  const update = (status: Incident["status"]) => {
    if (!sel) return;
    setData((d) => d.map((i) => (i.id === sel.id ? { ...i, status } : i)));
    setSel({ ...sel, status });
    toast.success(`${sel.id} marked ${status}`);
  };

  const handleCopyHash = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    toast.success("SHA-256 Hash copied to clipboard");
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleVerifyIntegrity = async () => {
    if (!sel) return;
    setVerifying(true);
    
    // Perform cryptographic SHA-256 verification
    const res = await verifyIncidentIntegrity(sel);
    setVerifying(false);

    if (res.verified) {
      toast.success(`${sel.id}: Cryptographic SHA-256 seal & chain verified!`, {
        description: `Digest matches registered hash: ${res.computedHash.slice(0, 16)}...`,
      });
    } else {
      toast.error(`${sel.id}: CRYPTOGRAPHIC INTEGRITY VIOLATION DETECTED!`, {
        description: `Computed hash (${res.computedHash.slice(0, 10)}...) does not match recorded seal (${res.expectedHash.slice(0, 10)}...).`,
      });
    }
  };

  const toggleTamperSimulation = () => {
    if (!sel) return;
    const isNowTampered = !sel.tampered;

    let updatedIncident: Incident;
    if (isNowTampered) {
      // Modify payload maliciously (e.g., downgrade Critical to Low, change description) without updating hash
      updatedIncident = {
        ...sel,
        severity: "Low",
        description: `[UNAUTHORIZED EDIT] Triage altered. Severity downgraded without valid cryptographic key.`,
        tampered: true,
      };
      toast.warning(`${sel.id}: Simulated unauthorized data modification applied.`);
    } else {
      // Restore valid original state
      const seedOriginal = seed.find((item) => item.id === sel.id);
      if (seedOriginal) {
        updatedIncident = { ...seedOriginal, tampered: false };
      } else {
        const correctHash = computeIncidentHashSync({
          id: sel.id,
          time: sel.time,
          type: sel.type,
          source: sel.source,
          severity: sel.severity,
          description: sel.description,
          prevHash: sel.prevHash,
        });
        updatedIncident = { ...sel, hash: correctHash, tampered: false };
      }
      toast.success(`${sel.id}: Cryptographic integrity restored to valid state.`);
    }

    setData((prev) => prev.map((item) => (item.id === sel.id ? updatedIncident : item)));
    setSel(updatedIncident);
  };

  return (
    <>
      <PageHeader
        title="Live Incidents"
        subtitle={`${rows.length} incidents match current filters · SHA-256 Immutable Audit Ledger`}
      />

      <Panel>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative min-w-60 flex-1">
            <Search className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search ID, type, source, SHA-256 hash…"
              className="pl-9"
            />
          </div>

          <div className="flex rounded-md border p-0.5">
            {kinds.map((k) => (
              <button
                key={k}
                onClick={() => setKind(k)}
                className={cn(
                  "rounded px-3 py-1.5 text-xs font-medium transition-colors",
                  kind === k
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {k}
              </button>
            ))}
          </div>

          <Select value={sev} onValueChange={setSev}>
            <SelectTrigger className="w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["All", "Low", "Medium", "High", "Critical"].map((s) => (
                <SelectItem key={s} value={s}>
                  {s === "All" ? "All severities" : s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={integrityFilter}
            onValueChange={(v) => setIntegrityFilter(v as (typeof integrityFilters)[number])}
          >
            <SelectTrigger className="w-40 font-mono text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {integrityFilters.map((f) => (
                <SelectItem key={f} value={f} className="text-xs">
                  {f}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
              <tr className="border-b">
                {[
                  "ID",
                  "Timestamp",
                  "Event",
                  "Type",
                  "Source",
                  "Severity",
                  "Risk",
                  "Integrity Seal",
                  "Status",
                ].map((h) => (
                  <th key={h} className="px-3 py-2 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr
                  key={i.id}
                  onClick={() => setSel(i)}
                  className={cn(
                    "cursor-pointer border-b border-border/50 hover:bg-accent/50 transition-colors",
                    sel?.id === i.id && "bg-accent/60"
                  )}
                >
                  <td className="px-3 py-2.5 font-mono text-xs text-cyan">{i.id}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{i.time}</td>
                  <td className="px-3 py-2.5 font-medium">{i.type}</td>
                  <td className="px-3 py-2.5 text-xs">{i.kind}</td>
                  <td className="px-3 py-2.5 text-xs text-muted-foreground">{i.source}</td>
                  <td className="px-3 py-2.5">
                    <SeverityBadge severity={i.severity} />
                  </td>
                  <td className="px-3 py-2.5 font-mono">{i.risk}</td>
                  <td className="px-3 py-2.5">
                    {i.tampered ? (
                      <span className="inline-flex items-center gap-1.5 rounded border border-critical/30 bg-critical/15 px-2 py-0.5 text-xs font-semibold text-critical">
                        <ShieldAlert className="size-3.5" /> Tampered
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded border border-success/30 bg-success/15 px-2 py-0.5 text-xs font-medium text-success">
                        <ShieldCheck className="size-3.5" /> Verified
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-xs">{i.status}</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-10 text-center text-muted-foreground">
                    No incidents match current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      <Sheet open={!!sel} onOpenChange={(o) => !o && setSel(null)}>
        <SheetContent className="sm:max-w-lg overflow-y-auto max-h-screen">
          {sel && (
            <>
              <SheetHeader>
                <div className="flex items-center justify-between">
                  <SheetTitle className="font-mono text-lg text-cyan">{sel.id}</SheetTitle>
                  {sel.tampered ? (
                    <span className="inline-flex items-center gap-1 rounded bg-critical/20 px-2 py-0.5 font-mono text-xs text-critical">
                      <ShieldAlert className="size-3.5" /> TAMPER DETECTED
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded bg-success/20 px-2 py-0.5 font-mono text-xs text-success">
                      <ShieldCheck className="size-3.5" /> CHAIN VERIFIED
                    </span>
                  )}
                </div>
                <SheetDescription>{sel.type}</SheetDescription>
              </SheetHeader>

              <div className="space-y-5 px-1 py-4">
                {/* Core incident attributes */}
                <dl className="grid grid-cols-2 gap-3 rounded-lg border bg-panel/50 p-3 text-sm">
                  {[
                    ["Timestamp", sel.time],
                    ["Category", sel.kind],
                    ["Source", sel.source],
                    ["Risk Score", sel.risk],
                    ["Status", sel.status],
                  ].map(([k, v]) => (
                    <div key={k as string}>
                      <dt className="text-xs text-muted-foreground">{k}</dt>
                      <dd className="font-medium">{v}</dd>
                    </div>
                  ))}
                  <div>
                    <dt className="text-xs text-muted-foreground">Severity</dt>
                    <dd>
                      <SeverityBadge severity={sel.severity} />
                    </dd>
                  </div>
                </dl>

                {/* Incident description */}
                <div className="space-y-1">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Incident Description
                  </label>
                  <p
                    className={cn(
                      "rounded-md border p-3 text-sm leading-relaxed",
                      sel.tampered
                        ? "border-critical/40 bg-critical/10 text-critical"
                        : "border-border bg-panel text-foreground"
                    )}
                  >
                    {sel.description}
                  </p>
                </div>

                {/* Forensic Cryptographic Seal & Ledger Card */}
                <div className="rounded-lg border border-cyan/20 bg-terminal/70 p-3.5 space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-border/40 pb-2">
                    <div className="flex items-center gap-1.5 font-semibold text-cyan">
                      <Lock className="size-3.5" /> Forensic Cryptographic Seal
                    </div>
                    <span className="rounded bg-cyan/10 px-1.5 py-0.5 text-[10px] text-cyan">
                      SHA-256 + Ed25519
                    </span>
                  </div>

                  {/* SHA-256 Digest */}
                  <div>
                    <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                      <span>Content Digest (SHA-256)</span>
                      <button
                        onClick={() => handleCopyHash(sel.hash)}
                        className="flex items-center gap-1 text-cyan hover:underline"
                      >
                        {copiedHash ? (
                          <Check className="size-3 text-success" />
                        ) : (
                          <Copy className="size-3" />
                        )}
                        <span>{copiedHash ? "Copied" : "Copy"}</span>
                      </button>
                    </div>
                    <div className="mt-1 break-all rounded bg-background/80 p-2 text-[11px] text-cyan border border-border/40">
                      {sel.hash}
                    </div>
                  </div>

                  {/* Previous Block Hash */}
                  <div>
                    <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                      <History className="size-3" /> Previous Block Hash (Ledger Link)
                    </span>
                    <div className="mt-1 truncate rounded bg-background/80 p-1.5 text-[11px] text-muted-foreground border border-border/40">
                      {sel.prevHash}
                    </div>
                  </div>

                  {/* Edge Signature */}
                  <div>
                    <span className="text-[11px] text-muted-foreground">Edge Signature Seal</span>
                    <div className="mt-1 truncate rounded bg-background/80 p-1.5 text-[11px] text-muted-foreground border border-border/40">
                      {sel.signature}
                    </div>
                  </div>

                  {/* Evidence Link */}
                  {sel.evidenceRef && (
                    <div className="flex items-center justify-between pt-1 text-xs">
                      <span className="text-muted-foreground">Forensic Evidence File:</span>
                      <Link
                        to="/evidence"
                        className="flex items-center gap-1 text-cyan hover:underline font-mono"
                      >
                        {sel.evidenceRef} <ExternalLink className="size-3" />
                      </Link>
                    </div>
                  )}
                </div>

                {/* Tamper Simulation & Verification Controls */}
                <div className="space-y-2">
                  <div className="flex gap-2">
                    <Button
                      className="flex-1"
                      onClick={handleVerifyIntegrity}
                      disabled={verifying}
                    >
                      {verifying ? (
                        <Loader2 className="mr-1.5 size-4 animate-spin" />
                      ) : (
                        <ShieldCheck className="mr-1.5 size-4" />
                      )}
                      Verify SHA-256 Integrity
                    </Button>

                    <Button
                      variant={sel.tampered ? "outline" : "destructive"}
                      className="flex-1 text-xs"
                      onClick={toggleTamperSimulation}
                    >
                      {sel.tampered ? (
                        <>
                          <RotateCcw className="mr-1.5 size-3.5" /> Restore Original
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="mr-1.5 size-3.5" /> Simulate Tamper
                        </>
                      )}
                    </Button>
                  </div>

                  {sel.tampered && (
                    <div className="rounded-md border border-critical/40 bg-critical/10 p-2.5 text-xs text-critical">
                      <p className="font-semibold flex items-center gap-1">
                        <AlertTriangle className="size-3.5" /> Tamper Detection Active
                      </p>
                      <p className="mt-1 text-[11px] text-critical/90">
                        The incident payload was modified, but the registered SHA-256 digest remains
                        fixed. Click <strong>Verify SHA-256 Integrity</strong> to observe how the
                        cryptographic checksum catches unauthorized changes immediately.
                      </p>
                    </div>
                  )}
                </div>

                {/* Incident Status Workflow */}
                <div className="border-t pt-3">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider block mb-2">
                    Operator Workflow Action
                  </label>
                  <div className="flex gap-2">
                    <Button
                      className="flex-1"
                      variant="secondary"
                      onClick={() => update("Investigating")}
                      disabled={sel.status === "Investigating"}
                    >
                      Investigate
                    </Button>
                    <Button
                      className="flex-1"
                      onClick={() => update("Resolved")}
                      disabled={sel.status === "Resolved"}
                    >
                      Resolve
                    </Button>
                  </div>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
