import { describe, it, expect, vi, beforeEach } from "vitest";
import { checkModelServer, runModelPrediction } from "@/lib/threat-model";

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
        modelName: "cctvmodel.keras",
        ready: true,
      }),
    } as Response);

    const status = await checkModelServer();
    expect(status.status).toBe("online");
    expect(status.modelName).toBe("cctvmodel.keras");
    expect(status.ready).toBe(true);
  });

  it("parses prediction result correctly", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: "success",
        isThreat: true,
        label: "THREAT DETECTED",
        threatType: "Violence / Physical Suspicious Activity",
        confidence: 0.9421,
        rawScore: 0.9421,
        threshold: 0.5,
        processingTimeMs: 310,
        framesProcessed: 15,
        sampledFrames: 15,
        model: "cctvmodel.keras",
      }),
    } as Response);

    const res = await runModelPrediction(["data:image/jpeg;base64,dummy"]);
    expect(res.isThreat).toBe(true);
    expect(res.label).toBe("THREAT DETECTED");
    expect(res.confidence).toBe(0.9421);
    expect(res.model).toBe("cctvmodel.keras");
  });
});

