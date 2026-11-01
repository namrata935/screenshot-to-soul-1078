export interface ModelStatus {
  status: "online" | "offline" | "error";
  modelName: string;
  modelPath?: string;
  inputShape?: number[];
  architecture?: string;
  labels?: {
    threat: string;
    normal: string;
  };
  ready: boolean;
}

export interface PredictionResult {
  status: "success" | "error";
  isThreat: boolean;
  label: "THREAT DETECTED" | "NORMAL / SECURE";
  threatType: string;
  confidence: number;
  rawScore: number;
  threshold: number;
  processingTimeMs: number;
  framesProcessed: number;
  sampledFrames: number;
  model: string;
  message?: string;
}

const SERVER_URLS = [
  "/api/model",
  "http://127.0.0.1:5005/api/model",
  "http://localhost:5005/api/model",
];

export async function checkModelServer(): Promise<ModelStatus> {
  for (const baseUrl of SERVER_URLS) {
    try {
      const res = await fetch(`${baseUrl}/status`, {
        method: "GET",
        signal: AbortSignal.timeout(1500),
      });
      if (res.ok) {
        const data = await res.json();
        return {
          status: "online",
          modelName: data.modelName || "cctvmodel.keras",
          modelPath: data.modelPath,
          inputShape: data.inputShape,
          architecture: data.architecture,
          labels: data.labels,
          ready: true,
        };
      }
    } catch {
      // Continue to next URL
    }
  }

  return {
    status: "offline",
    modelName: "cctvmodel.keras",
    ready: false,
  };
}

export async function runModelPrediction(
  frames: string[],
  threshold = 0.5,
): Promise<PredictionResult> {
  let lastError: Error | null = null;

  for (const baseUrl of SERVER_URLS) {
    try {
      const res = await fetch(`${baseUrl}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ frames, threshold }),
        signal: AbortSignal.timeout(30000),
      });

      if (res.ok) {
        const data = (await res.json()) as PredictionResult;
        return data;
      }
    } catch (err) {
      lastError = err as Error;
    }
  }

  throw lastError || new Error("Failed to connect to CCTV model server");
}

/**
 * Captures an array of base64 frames (128x128 JPEG) from a live webcam HTMLVideoElement
 * over a given duration (e.g. 15 frames over 1500ms).
 */
export async function captureWebcamSequence(
  video: HTMLVideoElement,
  count = 15,
  intervalMs = 100,
  onProgress?: (current: number, total: number) => void,
): Promise<string[]> {
  const canvas = document.createElement("canvas");
  canvas.width = 128;
  canvas.height = 128;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) throw new Error("Could not initialize canvas context");

  const frames: string[] = [];

  for (let i = 0; i < count; i++) {
    ctx.drawImage(video, 0, 0, 128, 128);
    frames.push(canvas.toDataURL("image/jpeg", 0.85));
    if (onProgress) onProgress(i + 1, count);
    if (i < count - 1) {
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  return frames;
}

/**
 * Samples equidistant frames from an uploaded video file using an in-memory video element.
 */
export async function extractFramesFromVideoElement(
  video: HTMLVideoElement,
  count = 15,
  onProgress?: (current: number, total: number) => void,
): Promise<string[]> {
  const canvas = document.createElement("canvas");
  canvas.width = 128;
  canvas.height = 128;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) throw new Error("Could not initialize canvas context");

  const duration = video.duration || 1;
  const frames: string[] = [];
  const originalTime = video.currentTime;

  const seekTo = (time: number): Promise<void> =>
    new Promise((resolve) => {
      const handleSeeked = () => {
        video.removeEventListener("seeked", handleSeeked);
        resolve();
      };
      video.addEventListener("seeked", handleSeeked);
      video.currentTime = Math.min(Math.max(0, time), duration);
    });

  try {
    for (let i = 0; i < count; i++) {
      const targetTime = ((i + 0.5) / count) * duration;
      await seekTo(targetTime);
      ctx.drawImage(video, 0, 0, 128, 128);
      frames.push(canvas.toDataURL("image/jpeg", 0.85));
      if (onProgress) onProgress(i + 1, count);
    }
  } finally {
    // Restore original video position
    video.currentTime = originalTime;
  }

  return frames;
}

