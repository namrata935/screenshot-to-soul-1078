import os
import io
import time
import base64
from typing import List

# Setup environment for Keras before imports
os.environ.setdefault("KERAS_BACKEND", "tensorflow")
os.environ.setdefault("KERAS_HOME", "/tmp/.keras")

from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
import numpy as np
import keras

LOCAL_MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cctvmodel.keras")
DOWNLOADS_MODEL = "/Users/namratasrinivasa/Downloads/cctvmodel.keras"
MODEL_PATH = LOCAL_MODEL if os.path.exists(LOCAL_MODEL) else DOWNLOADS_MODEL

app = Flask(__name__)
CORS(app)

print(f"[*] Loading model from {MODEL_PATH}...")
start_time = time.time()
try:
    model = keras.models.load_model(MODEL_PATH)
    print(f"[+] Model loaded successfully in {time.time() - start_time:.2f}s")
    # Warmup prediction with zeros
    warmup_tensor = np.zeros((1, 15, 128, 128, 3), dtype=np.float32)
    _ = model.predict(warmup_tensor, verbose=0)
    print("[+] Model warmup completed.")
except Exception as e:
    print(f"[!] Error loading model: {e}")
    model = None


def decode_base64_image(b64_str: str) -> np.ndarray:
    """Decodes a base64 data URL or raw base64 string into a 128x128 RGB numpy array."""
    if "," in b64_str:
        b64_str = b64_str.split(",", 1)[1]
    img_bytes = base64.b64decode(b64_str)
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    img = img.resize((128, 128), Image.Resampling.BILINEAR)
    arr = np.array(img, dtype=np.float32)
    # MobileNetV2 preprocessing: map [0, 255] -> [-1, 1]
    arr = (arr / 127.5) - 1.0
    return arr


def sample_15_frames(frames: List[np.ndarray]) -> np.ndarray:
    """Ensure exactly 15 frames by uniform sampling or repetition."""
    n = len(frames)
    if n == 0:
        raise ValueError("No frames provided")
    if n == 15:
        selected = frames
    elif n < 15:
        # Repeat indices to reach 15
        indices = np.linspace(0, n - 1, 15).round().astype(int)
        selected = [frames[i] for i in indices]
    else:
        # Uniformly sample 15 frames from the sequence
        indices = np.linspace(0, n - 1, 15).round().astype(int)
        selected = [frames[i] for i in indices]
    
    # Return shape (1, 15, 128, 128, 3)
    return np.expand_dims(np.stack(selected, axis=0), axis=0)


@app.route("/health", methods=["GET"])
@app.route("/api/model/status", methods=["GET"])
def model_status():
    return jsonify({
        "status": "online" if model is not None else "error",
        "modelName": "cctvmodel.keras",
        "modelPath": MODEL_PATH,
        "inputShape": [None, 15, 128, 128, 3],
        "architecture": "MobileNetV2 + TimeDistributed + LSTM Sequence Classifier",
        "labels": {
            "threat": "Threat / Violence Detected",
            "normal": "Normal / Secure Activity"
        },
        "targetFps": 15,
        "ready": model is not None
    })


@app.route("/api/model/predict", methods=["POST"])
def predict():
    if model is None:
        return jsonify({"status": "error", "message": "Model not loaded"}), 500

    data = request.get_json(silent=True) or {}
    raw_frames = data.get("frames", [])
    threshold = float(data.get("threshold", 0.5))

    if not raw_frames:
        return jsonify({"status": "error", "message": "No 'frames' list provided in JSON"}), 400

    start_infer = time.time()
    try:
        processed_frames = [decode_base64_image(f) for f in raw_frames]
        tensor = sample_15_frames(processed_frames)
        
        # Inference
        pred = model.predict(tensor, verbose=0)
        raw_score = float(pred[0][0])
        
        # Binary classification
        # Score close to 1 indicates Threat / Violence; close to 0 indicates Normal
        is_threat = raw_score >= threshold
        confidence = raw_score if is_threat else (1.0 - raw_score)
        
        inference_time_ms = round((time.time() - start_infer) * 1000)

        return jsonify({
            "status": "success",
            "isThreat": is_threat,
            "label": "THREAT DETECTED" if is_threat else "NORMAL / SECURE",
            "threatType": "Violence / Physical Suspicious Activity" if is_threat else "None",
            "confidence": round(confidence, 4),
            "rawScore": round(raw_score, 4),
            "threshold": threshold,
            "processingTimeMs": inference_time_ms,
            "framesProcessed": len(raw_frames),
            "sampledFrames": 15,
            "model": "cctvmodel.keras"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5005))
    print(f"[*] Starting CCTV Threat Detection Server on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
