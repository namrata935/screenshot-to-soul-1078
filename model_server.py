import os
import sys
import io
import time
import base64
import logging
from typing import List, Dict, Any

# Setup environment for Keras & Ultralytics
os.environ.setdefault("KERAS_BACKEND", "tensorflow")
os.environ.setdefault("KERAS_HOME", "/tmp/.keras")
os.environ.setdefault("YOLO_CONFIG_DIR", "/tmp/.ultralytics")
os.environ.setdefault("MPLCONFIGDIR", "/tmp")

from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import numpy as np
import cv2

from ai_engine.cctv_ai_pipeline import CCTVThreatEngine
from ai_engine.training.evaluate import get_model_performance_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("model_server")

LOCAL_KERAS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cctvmodel.keras")
DOWNLOADS_KERAS = "/Users/namratasrinivasa/Downloads/cctvmodel.keras"
KERAS_PATH = LOCAL_KERAS if os.path.exists(LOCAL_KERAS) else DOWNLOADS_KERAS

YOLO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yolov8n.pt")

app = Flask(__name__)
CORS(app)

logger.info("[*] Initializing CCTV Multi-Threat Engine...")
engine = CCTVThreatEngine(
    keras_model_path=KERAS_PATH if os.path.exists(KERAS_PATH) else None,
    yolo_model_path=YOLO_PATH if os.path.exists(YOLO_PATH) else "yolov8n.pt"
)
logger.info("[+] CCTV Multi-Threat Engine online!")


def decode_base64_to_cv2(b64_str: str) -> np.ndarray:
    """Decodes a base64 image string into an RGB numpy array."""
    if "," in b64_str:
        b64_str = b64_str.split(",", 1)[1]
    img_bytes = base64.b64decode(b64_str)
    pil_img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    return np.array(pil_img, dtype=np.uint8)


@app.route("/health", methods=["GET"])
@app.route("/api/model/status", methods=["GET"])
@app.route("/api/ai/status", methods=["GET"])
def model_status():
    return jsonify({
        "status": "online",
        "ready": True,
        "models": {
            "yolo": {
                "name": "YOLOv8n",
                "ready": engine.yolo is not None,
                "classes": "COCO (persons, bags, laptops, phones)",
                "device": getattr(engine.yolo, "device", "cpu") if engine.yolo else "unavailable"
            },
            "pose": {
                "name": "MediaPipe Pose",
                "ready": engine.pose_estimator is not None,
                "landmarks": 33
            },
            "kerasLstm": {
                "name": "cctvmodel.keras",
                "path": KERAS_PATH,
                "ready": engine.keras_model is not None,
                "architecture": "MobileNetV2 + TimeDistributed + LSTM Sequence Classifier"
            },
            "incidentEngine": {
                "ready": True,
                "capabilities": [
                    "Fall Detection (Trajectory + Horizontal Posture + Lack of Motion)",
                    "Theft Detection (Valuable Objects + Ownership Association + Removal)",
                    "Physical Attack & Strike Detection (Wrist velocity vectors)",
                    "Proximity Violence & Altercations",
                    "Restricted Perimeter Intrusion & Tripwire Line Crossing"
                ]
            }
        },
        "metrics": get_model_performance_metrics(),
        "modelName": "CCTV Threat Multi-Model Suite (YOLOv8 + MediaPipe + cctvmodel.keras)",
        "targetFps": 15
    })


@app.route("/api/model/metrics", methods=["GET"])
def model_metrics():
    """Returns validation metrics computed from ai_engine.training.evaluate."""
    return jsonify(get_model_performance_metrics())


@app.route("/api/model/predict", methods=["POST"])
def predict():
    """
    Standard sequence prediction endpoint (supports 15-frame sequence from webcam or video).
    Enriched with full incident detection, YOLO detections, pose estimation, and annotated visualization.
    """
    data = request.get_json(silent=True) or {}
    raw_frames = data.get("frames", [])
    threshold = float(data.get("threshold", 0.5))

    if not raw_frames:
        return jsonify({"status": "error", "message": "No 'frames' provided in request"}), 400

    try:
        cv2_frames = [decode_base64_to_cv2(f) for f in raw_frames]
        result = engine.analyze_sequence(cv2_frames, threshold=threshold, return_annotated=True)

        keras_res = result.get("kerasResult") or {}
        raw_score = keras_res.get("rawScore", 0.0)
        confidence = keras_res.get("confidence", 0.5)

        # Merge backwards-compatible fields with new multi-modal fields
        return jsonify({
            "status": "success",
            "isThreat": result["isThreat"],
            "label": result["label"],
            "threatType": result["threatType"],
            "confidence": confidence,
            "rawScore": raw_score,
            "threshold": threshold,
            "severity": result.get("severity", "Low"),
            "maxSeverityScore": result.get("maxSeverityScore", 0),
            "processingTimeMs": result["processingTimeMs"],
            "framesProcessed": len(raw_frames),
            "sampledFrames": 15,
            "model": "cctvmodel.keras + YOLOv8 + MediaPipe",
            "incidents": result.get("incidents", []),
            "incidentsCount": result.get("incidentsCount", 0),
            "objects": result.get("objects", []),
            "poses": result.get("poses", []),
            "annotatedFrame": result.get("annotatedFrame")
        })
    except Exception as e:
        logger.error(f"Inference error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/ai/analyze-frame", methods=["POST"])
def analyze_single_frame():
    """
    Real-time single frame analysis endpoint for live webcam feed.
    Returns annotated frame with bounding boxes & skeleton, detected objects, and active alerts.
    """
    data = request.get_json(silent=True) or {}
    frame_b64 = data.get("frame")
    conf_threshold = float(data.get("confThreshold", 0.35))

    if not frame_b64:
        return jsonify({"status": "error", "message": "No 'frame' provided"}), 400

    try:
        cv2_frame = decode_base64_to_cv2(frame_b64)
        result = engine.analyze_frame(cv2_frame, return_annotated=True, conf_threshold=conf_threshold)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Single frame analysis error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/ai/reset", methods=["POST"])
def reset_engine():
    """Reset tracker and detector states."""
    try:
        engine.incident_detector.reset()
        engine.fall_detector.reset()
        engine.theft_detector.reset()
        engine.tracker = ByteTracker(max_age=20, min_hits=2)
        return jsonify({"status": "success", "message": "AI Engine state reset"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


import socket
import argparse
import subprocess


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if a TCP port is currently open and bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((host, port)) == 0


def find_next_available_port(start_port: int, max_trials: int = 20) -> int:
    """Finds the next unallocated port starting from start_port."""
    for p in range(start_port, start_port + max_trials):
        if not is_port_in_use(p):
            return p
    return start_port


def kill_process_on_port(port: int):
    """Attempts to kill existing process occupying the given port."""
    try:
        pids = subprocess.check_output(["lsof", "-ti", f":{port}"], text=True).strip().splitlines()
        for p in pids:
            pid = int(p.strip())
            if pid != os.getpid():
                logger.info(f"[*] Terminating existing process {pid} on port {port}...")
                os.kill(pid, 9)
        time.sleep(0.5)
    except Exception as e:
        logger.debug(f"Could not kill process on port {port}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCTV Multi-Detection AI Model Server")
    parser.add_argument("--port", "-p", type=int, default=None, help="Port to run on (or set PORT env var)")
    parser.add_argument("--host", "-H", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--kill", "-k", action="store_true", help="Kill any existing process on target port before starting")
    parser.add_argument("--no-fallback", action="store_true", help="Do not auto-search for next free port if occupied")
    args = parser.parse_args()

    desired_port = args.port or int(os.environ.get("PORT", 5005))

    if args.kill and is_port_in_use(desired_port):
        kill_process_on_port(desired_port)

    active_port = desired_port
    if is_port_in_use(desired_port):
        if args.no_fallback:
            logger.error(f"[-] Port {desired_port} is already in use and fallback is disabled.")
            logger.error(f"    Run 'lsof -ti:{desired_port} | xargs kill -9' to free it, or choose a different port.")
            sys.exit(1)
        else:
            active_port = find_next_available_port(desired_port + 1)
            logger.warning("=" * 60)
            logger.warning(f"⚠️  PORT {desired_port} IS ALREADY IN USE BY ANOTHER PROGRAM!")
            logger.warning(f"👉 Automatically switching to next available port: {active_port}")
            logger.warning(f"💡 Tip: To free port {desired_port}, run:")
            logger.warning(f"      lsof -ti:{desired_port} | xargs kill -9")
            logger.warning("=" * 60)

    logger.info(f"[*] Starting CCTV Multi-Detection AI Server on {args.host}:{active_port}...")
    try:
        app.run(host=args.host, port=active_port, debug=False)
    except OSError as e:
        if "Address already in use" in str(e):
            fallback = find_next_available_port(active_port + 1)
            logger.warning(f"⚠️  Address in use during bind. Retrying on port {fallback}...")
            app.run(host=args.host, port=fallback, debug=False)
        else:
            raise
