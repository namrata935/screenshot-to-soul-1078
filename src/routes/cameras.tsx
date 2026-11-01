import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Plus, Eye, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, StatusDot, VideoPlaceholder } from "@/components/vms/ui";
import { cameras as seed, type Camera } from "@/lib/mock-data";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { pageHead } from "@/lib/meta";

export const Route = createFileRoute("/cameras")({
  head: pageHead("Camera Management", "Add, view and remove webcam and RTSP surveillance cameras."),
  component: Cameras,
});

function Cameras() {
  const [list, setList] = useState<Camera[]>(seed);
  const [adding, setAdding] = useState(false);
  const [viewing, setViewing] = useState<Camera | null>(null);
  const [form, setForm] = useState({ name: "", location: "", source: "RTSP" as Camera["source"], url: "" });

  const add = () => {
    if (!form.name.trim()) return toast.error("Camera name is required");
    const id = `CAM-${String(100 + list.length).padStart(3, "0")}`;
    setList((l) => [...l, { id, name: form.name, location: form.location || "Unassigned", online: true, source: form.source, fps: 25 }]);
    setAdding(false); setForm({ name: "", location: "", source: "RTSP", url: "" });
    toast.success(`${id} added`);
  };

  return (
    <>
      <PageHeader title="Camera Management" subtitle={`${list.filter((c) => c.online).length} of ${list.length} cameras online`}
        actions={<Button onClick={() => setAdding(true)}><Plus className="size-4" /> Add Camera</Button>} />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {list.map((c) => (
          <div key={c.id} className="panel p-3">
            <VideoPlaceholder label={`${c.id} · ${c.fps} FPS`} offline={!c.online} />
            <div className="mt-3 flex items-start justify-between">
              <div>
                <p className="text-sm font-medium">{c.name}</p>
                <p className="text-xs text-muted-foreground">{c.location}</p>
                <p className="mt-1 font-mono text-[11px] text-cyan">{c.id} · {c.source}</p>
              </div>
              <span className="flex items-center gap-1.5 text-xs"><StatusDot tone={c.online ? "success" : "critical"} />{c.online ? "Online" : "Offline"}</span>
            </div>
            <div className="mt-3 flex gap-2">
              <Button size="sm" variant="secondary" className="flex-1" onClick={() => setViewing(c)}><Eye className="size-3.5" /> View</Button>
              <Button size="sm" variant="ghost" onClick={() => { setList((l) => l.filter((x) => x.id !== c.id)); toast(`${c.id} removed`); }} aria-label="Remove"><Trash2 className="size-3.5 text-critical" /></Button>
            </div>
          </div>
        ))}
      </div>

      <Dialog open={adding} onOpenChange={setAdding}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add camera</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              {(["Webcam", "RTSP"] as const).map((s) => (
                <button key={s} onClick={() => setForm({ ...form, source: s })} className={cn("rounded-md border p-3 text-left text-sm", form.source === s ? "border-primary bg-primary/10" : "hover:bg-accent")}>
                  <p className="font-medium">{s === "Webcam" ? "Local Webcam" : "RTSP Stream"}</p>
                  <p className="text-xs text-muted-foreground">{s === "Webcam" ? "USB / built-in device" : "IP camera over network"}</p>
                </button>
              ))}
            </div>
            <div className="space-y-1.5"><Label>Name</Label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Rooftop East" /></div>
            <div className="space-y-1.5"><Label>Location</Label><Input value={form.location} onChange={(e) => setForm({ ...form, location: e.target.value })} placeholder="Building / zone" /></div>
            {form.source === "RTSP" && <div className="space-y-1.5"><Label>RTSP URL</Label><Input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="rtsp://user:pass@10.0.0.5:554/stream1" className="font-mono text-xs" /></div>}
          </div>
          <DialogFooter><Button variant="ghost" onClick={() => setAdding(false)}>Cancel</Button><Button onClick={add}>Add camera</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!viewing} onOpenChange={(o) => !o && setViewing(null)}>
        <DialogContent className="sm:max-w-2xl">
          {viewing && (<>
            <DialogHeader><DialogTitle>{viewing.name} <span className="font-mono text-sm text-cyan">{viewing.id}</span></DialogTitle></DialogHeader>
            <VideoPlaceholder label={`LIVE · ${viewing.id}`} offline={!viewing.online} />
            <p className="text-sm text-muted-foreground">{viewing.location} · {viewing.source} · {viewing.fps} FPS</p>
          </>)}
        </DialogContent>
      </Dialog>
    </>
  );
}
