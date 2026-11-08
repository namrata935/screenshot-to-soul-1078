export interface IncidentItem {
  type: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  severityScore: number;
  confidence: number;
  description: string;
  camera_id?: string;
  timestamp?: number;
  bbox?: number[];
  object_id?: string;
}

export interface DetectedObject {
  bbox: [number, number, number, number];
  conf: number;
  class: number;
  class_name: string;
}

export interface DetectedPose {
  keypoints: [number, number, number][];
  conf: number;
  num_keypoints: number;
  bbox: [number, number, number, number];
}

export interface ModelMetrics {
  accuracy?: number;
  f1_score?: number;
  precision?: number;
  recall?: number;
  auc_roc?: number;
  detector_mAP50?: number;
  detector_precision?: number;
  detector_recall?: number;
}

export interface ModelStatus {
  status: "online" | "offline" | "error";
  modelName: string;
  modelPath?: string;
  ready: boolean;
  metrics?: ModelMetrics;
  models?: {
    yolo?: { name: string; ready: boolean; classes: string; device: string };
    pose?: { name: string; ready: boolean; landmarks: number };
    kerasLstm?: { name: string; ready: boolean; architecture: string };
    incidentEngine?: { ready: boolean; capabilities: string[] };
  };
}

export interface PredictionResult {
  status: "success" | "error";
  isThreat: boolean;
  label: "THREAT DETECTED" | "NORMAL / SECURE";
  threatType: string;
  confidence: number;
  rawScore: number;
  threshold: number;
  severity?: "Critical" | "High" | "Medium" | "Low";
  maxSeverityScore?: number;
  processingTimeMs: number;
  framesProcessed: number;
  sampledFrames: number;
  model: string;
  incidents?: IncidentItem[];
  incidentsCount?: number;
  objects?: DetectedObject[];
  poses?: DetectedPose[];
  annotatedFrame?: string;
  message?: string;
}

export interface SingleFrameResult {
  status: "success" | "warning" | "error";
  frameNumber?: number;
  processingTimeMs: number;
  objectsCount: number;
  objects: DetectedObject[];
  posesCount: number;
  poses: DetectedPose[];
  incidents: IncidentItem[];
  hasIncident: boolean;
  annotatedFrame?: string;
  message?: string;
}

const SERVER_URLS = [
  "/api/model",
  "http://127.0.0.1:5005/api/model",
  "http://localhost:5005/api/model",
  "http://127.0.0.1:5006/api/model",
  "http://localhost:5006/api/model",
  "http://127.0.0.1:5007/api/model",
  "http://localhost:5007/api/model",
  "http://127.0.0.1:5008/api/model",
  "http://localhost:5008/api/model",
];

const AI_URLS = [
  "/api/ai",
  "http://127.0.0.1:5005/api/ai",
  "http://localhost:5005/api/ai",
  "http://127.0.0.1:5006/api/ai",
  "http://localhost:5006/api/ai",
  "http://127.0.0.1:5007/api/ai",
  "http://localhost:5007/api/ai",
  "http://127.0.0.1:5008/api/ai",
  "http://localhost:5008/api/ai",
];

export async function checkModelServer(): Promise<ModelStatus> {
  for (const baseUrl of SERVER_URLS) {
    try {
      const res = await fetch(`${baseUrl}/status`, {
        method: "GET",
        signal: AbortSignal.timeout(2000),
      });
      if (res.ok) {
        const data = await res.json();
        return {
          status: "online",
          modelName: data.modelName || "CCTV Threat Multi-Model Suite",
          modelPath: data.modelPath,
          ready: Boolean(data.ready),
          models: data.models,
          metrics: data.metrics,
        };
      }
    } catch {
      // Continue to next URL
    }
  }

  return {
    status: "offline",
    modelName: "CCTV Multi-Detection Suite",
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
        signal: AbortSignal.timeout(45000),
      });

      if (res.ok) {
        const data = (await res.json()) as PredictionResult;
        return data;
      }
    } catch (err) {
      lastError = err as Error;
    }
  }

  throw lastError || new Error("Failed to connect to CCTV AI model server");
}

export async function analyzeLiveFrame(
  frameBase64: string,
  confThreshold = 0.35,
): Promise<SingleFrameResult> {
  for (const baseUrl of AI_URLS) {
    try {
      const res = await fetch(`${baseUrl}/analyze-frame`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ frame: frameBase64, confThreshold }),
        signal: AbortSignal.timeout(5000),
      });

      if (res.ok) {
        return (await res.json()) as SingleFrameResult;
      }
    } catch {
      // Continue to next URL
    }
  }

  throw new Error("Live frame analysis unavailable");
}

export async function resetAiEngine(): Promise<void> {
  for (const baseUrl of AI_URLS) {
    try {
      await fetch(`${baseUrl}/reset`, { method: "POST" });
      return;
    } catch {
      // Continue
    }
  }
}

/**
 * Captures an array of base64 frames (640x480 or native aspect ratio) from a live webcam
 */
export async function captureWebcamSequence(
  video: HTMLVideoElement,
  count = 15,
  intervalMs = 100,
  onProgress?: (current: number, total: number) => void,
): Promise<string[]> {
  const canvas = document.createElement("canvas");
  const w = video.videoWidth || 640;
  const h = video.videoHeight || 480;
  canvas.width = Math.min(640, w);
  canvas.height = Math.round(canvas.width * (h / w));
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) throw new Error("Could not initialize canvas context");

  const frames: string[] = [];

  for (let i = 0; i < count; i++) {
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
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
  const w = video.videoWidth || 640;
  const h = video.videoHeight || 480;
  canvas.width = Math.min(640, w);
  canvas.height = Math.round(canvas.width * (h / w));
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
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      frames.push(canvas.toDataURL("image/jpeg", 0.85));
      if (onProgress) onProgress(i + 1, count);
    }
  } finally {
    video.currentTime = originalTime;
  }

  return frames;
}
