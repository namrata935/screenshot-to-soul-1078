import { describe, it, expect, vi, beforeEach } from "vitest";
import { checkModelServer, runModelPrediction, analyzeLiveFrame } from "@/lib/threat-model";

describe("Threat Model Integration", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns offline status when server is unreachable", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network down"));
    const status = await checkModelServer();
    expect(status.status).toBe("offline");
    expect(status.ready).toBe(false);
  });

  it("returns online status when server responds successfully", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: "online",
        modelName: "CCTV Threat Multi-Model Suite",
        ready: true,
        models: {
          yolo: { name: "YOLOv8n", ready: true },
          pose: { name: "MediaPipe Pose", ready: true },
          kerasLstm: { name: "cctvmodel.keras", ready: true },
        },
      }),
    } as Response);

    const status = await checkModelServer();
    expect(status.status).toBe("online");
    expect(status.ready).toBe(true);
    expect(status.models?.yolo?.ready).toBe(true);
  });

  it("parses multi-threat prediction result with incidents and objects correctly", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: "success",
        isThreat: true,
        label: "THREAT DETECTED",
        threatType: "Physical Violence / Altercation Sequence",
        confidence: 0.9421,
        rawScore: 0.9421,
        threshold: 0.5,
        severity: "Critical",
        maxSeverityScore: 92,
        processingTimeMs: 310,
        framesProcessed: 15,
        sampledFrames: 15,
        model: "cctvmodel.keras + YOLOv8 + MediaPipe",
        incidents: [
          {
            type: "fall_detected",
            severity: "Critical",
            severityScore: 92,
            confidence: 0.89,
            description: "Person fall detected: rapid downward trajectory",
          },
        ],
        incidentsCount: 1,
        objects: [
          { bbox: [100, 100, 200, 300], conf: 0.95, class: 0, class_name: "person" },
          { bbox: [220, 250, 280, 320], conf: 0.85, class: 24, class_name: "backpack" },
        ],
      }),
    } as Response);

    const res = await runModelPrediction(["data:image/jpeg;base64,dummy"]);
    expect(res.isThreat).toBe(true);
    expect(res.label).toBe("THREAT DETECTED");
    expect(res.severity).toBe("Critical");
    expect(res.incidentsCount).toBe(1);
    expect(res.incidents?.[0].type).toBe("fall_detected");
    expect(res.objects?.length).toBe(2);
  });

  it("handles live single frame analysis", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: "success",
        frameNumber: 1,
        processingTimeMs: 45,
        objectsCount: 1,
        objects: [{ bbox: [50, 50, 150, 250], conf: 0.91, class: 0, class_name: "person" }],
        posesCount: 1,
        poses: [],
        incidents: [],
        hasIncident: false,
        annotatedFrame: "data:image/jpeg;base64,annotated",
      }),
    } as Response);

    const liveRes = await analyzeLiveFrame("data:image/jpeg;base64,dummy", 0.35);
    expect(liveRes.status).toBe("success");
    expect(liveRes.objectsCount).toBe(1);
    expect(liveRes.hasIncident).toBe(false);
    expect(liveRes.annotatedFrame).toBe("data:image/jpeg;base64,annotated");
  });

  it("correctly evaluates nominal peaceful pedestrian sequence as normal and secure", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: "success",
        isThreat: false,
        label: "NORMAL / SECURE",
        threatType: "Normal Activity / Peaceful Pedestrians",
        confidence: 0.95,
        rawScore: 0.12,
        threshold: 0.5,
        severity: "Low",
        maxSeverityScore: 0,
        processingTimeMs: 180,
        framesProcessed: 15,
        sampledFrames: 15,
        model: "cctvmodel.keras + YOLOv8 + MediaPipe",
        incidents: [],
        incidentsCount: 0,
        objects: [
          { bbox: [100, 100, 200, 300], conf: 0.91, class: 0, class_name: "person" },
          { bbox: [350, 120, 450, 320], conf: 0.88, class: 0, class_name: "person" },
        ],
      }),
    } as Response);

    const res = await runModelPrediction([
      "data:image/jpeg;base64,frame1",
      "data:image/jpeg;base64,frame2",
    ]);
    expect(res.isThreat).toBe(false);
    expect(res.label).toBe("NORMAL / SECURE");
    expect(res.severity).toBe("Low");
    expect(res.incidentsCount).toBe(0);
    expect(res.threatType).toBe("Normal Activity / Peaceful Pedestrians");
    expect(res.confidence).toBe(0.95);
  });
});
