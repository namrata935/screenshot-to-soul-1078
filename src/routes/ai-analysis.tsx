import { useEffect, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Camera, Upload, Play, Square, ScanSearch, ShieldAlert, ShieldCheck, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel } from "@/components/vms/ui";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/ai-analysis")({
  head: pageHead("AI Video Analysis", "Binary violence / non-violence classification from webcam or uploaded video (simulated)."),
  component: AiAnalysis,
});

type Result = { label: "VIOLENCE" | "NON-VIOLENCE"; confidence: number; ms: number; frames: number };

function AiAnalysis() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [camOn, setCamOn] = useState(false);
  const [file, setFile] = useState<{ url: string; name: string } | null>(null);
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);

  useEffect(() => () => streamRef.current?.getTracks().forEach((t) => t.stop()), []);

  const startCam = async () => {
    try {
      const s = await navigator.mediaDevices.getUserMedia({ video: true });
      streamRef.current = s;
      if (videoRef.current) videoRef.current.srcObject = s;
      setCamOn(true);
    } catch { toast.error("Camera permission denied or unavailable"); }
  };
  const stopCam = () => { streamRef.current?.getTracks().forEach((t) => t.stop()); streamRef.current = null; setCamOn(false); };

  const pick = (f?: File) => {
    if (!f) return;
    // eslint-disable-next-line

    if (!f.type.startsWith("video/")) { toast.error("Please choose a video file"); return; }
    if (file) URL.revokeObjectURL(file.url);
    setFile({ url: URL.createObjectURL(f), name: f.name }); setResult(null);
  };

  const analyze = (ready: boolean) => {
    if (!ready) { toast.error("Start the camera or upload a video first"); return; }
    setBusy(true); setResult(null);
    const ms = 900 + Math.round(Math.random() * 900);
    setTimeout(() => {
      const violent = Math.random() < 0.45;
      setResult({ label: violent ? "VIOLENCE" : "NON-VIOLENCE", confidence: 0.78 + Math.random() * 0.2, ms, frames: 48 + Math.round(Math.random() * 80) });
      setBusy(false);
    }, ms);
  };

  return (
    <>
      <PageHeader title="AI Video Analysis" subtitle="Binary classifier: VIOLENCE / NON-VIOLENCE · results are simulated" />
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="xl:col-span-2">
          <Tabs defaultValue="webcam" onValueChange={() => setResult(null)}>
            <TabsList><TabsTrigger value="webcam"><Camera className="size-4" /> Laptop Webcam</TabsTrigger><TabsTrigger value="upload"><Upload className="size-4" /> Upload Video</TabsTrigger></TabsList>
            <TabsContent value="webcam" className="mt-4 space-y-3">
              <div className="grid-bg relative flex aspect-video items-center justify-center overflow-hidden rounded-md border bg-terminal">
                <video ref={videoRef} autoPlay muted playsInline className={cn("h-full w-full object-cover", !camOn && "hidden")} />
                {!camOn && <span className="font-mono text-xs text-muted-foreground">CAMERA OFF</span>}
              </div>
              <div className="flex flex-wrap gap-2">
                {camOn ? <Button variant="secondary" onClick={stopCam}><Square className="size-4" /> Stop Camera</Button> : <Button variant="secondary" onClick={startCam}><Play className="size-4" /> Start Camera</Button>}
                <Button onClick={() => analyze(camOn)} disabled={busy}>{busy ? <Loader2 className="size-4 animate-spin" /> : <ScanSearch className="size-4" />} Analyze Frame Window</Button>
              </div>
            </TabsContent>
            <TabsContent value="upload" className="mt-4 space-y-3">
              {file ? (
                <video src={file.url} controls className="aspect-video w-full rounded-md border bg-terminal" />
              ) : (
                <label
                  onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
                  onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]); }}
                  className={cn("flex aspect-video cursor-pointer flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed text-sm text-muted-foreground", drag ? "border-primary bg-primary/10" : "hover:border-primary/60")}
                >
                  <Upload className="size-8" /> Drag & drop a video, or click to browse
                  <span className="text-xs">MP4, WebM, MOV · stays on your device</span>
                  <input type="file" accept="video/*" className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
                </label>
              )}
              <div className="flex flex-wrap items-center gap-2">
                <Button onClick={() => analyze(!!file)} disabled={busy}>{busy ? <Loader2 className="size-4 animate-spin" /> : <ScanSearch className="size-4" />} Analyze Video</Button>
                {file && <Button variant="ghost" onClick={() => { URL.revokeObjectURL(file.url); setFile(null); setResult(null); }}>Clear</Button>}
                {file && <span className="truncate font-mono text-xs text-muted-foreground">{file.name}</span>}
              </div>
            </TabsContent>
          </Tabs>
        </Panel>

        <Panel title="Analysis result">
          {busy && <div className="flex flex-col items-center gap-3 py-12 text-sm text-muted-foreground"><Loader2 className="size-8 animate-spin text-primary" /> Running inference…</div>}
          {!busy && !result && <p className="py-12 text-center text-sm text-muted-foreground">No analysis yet.</p>}
          {!busy && result && (() => {
            const v = result.label === "VIOLENCE";
            return (
              <div className="space-y-4">
                <div className={cn("rounded-lg border p-5 text-center", v ? "glow-critical border-critical bg-critical/15" : "glow-success border-success bg-success/15")}>
                  {v ? <ShieldAlert className="mx-auto size-10 text-critical" /> : <ShieldCheck className="mx-auto size-10 text-success" />}
                  <p className={cn("mt-2 text-2xl font-bold tracking-wider", v ? "text-critical" : "text-success")}>{result.label}</p>
                  <p className="text-xs text-muted-foreground">{v ? "Alert dispatched to SOC (simulated)" : "No threat detected"}</p>
                </div>
                <dl className="grid grid-cols-3 gap-2 text-center">
                  {[["Confidence", `${(result.confidence * 100).toFixed(1)}%`], ["Processing", `${result.ms} ms`], ["Frames", result.frames]].map(([k, val]) => (
                    <div key={k as string} className="rounded-md border bg-panel p-2"><dt className="text-[10px] uppercase text-muted-foreground">{k}</dt><dd className="font-mono text-sm">{val}</dd></div>
                  ))}
                </dl>
                <div>
                  <div className="mb-1 flex justify-between text-xs"><span>Confidence</span><span className="font-mono">{(result.confidence * 100).toFixed(1)}%</span></div>
                  <div className="h-2 rounded bg-muted"><div className={cn("h-full rounded", v ? "bg-critical" : "bg-success")} style={{ width: `${result.confidence * 100}%` }} /></div>
                </div>
              </div>
            );
          })()}
        </Panel>
      </div>
    </>
  );
}
