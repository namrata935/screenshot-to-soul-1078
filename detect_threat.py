#!/usr/bin/env python3
"""
detect_threat.py - Standalone CLI for testing cctvmodel.keras

Usage:
    python3 detect_threat.py <image_path_or_folder>
    python3 detect_threat.py frame1.jpg frame2.jpg ... frame15.jpg
"""

import sys
import os
import glob
from typing import List

os.environ.setdefault("KERAS_BACKEND", "tensorflow")
os.environ.setdefault("KERAS_HOME", "/tmp/.keras")

from PIL import Image
import numpy as np
import keras

LOCAL_MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cctvmodel.keras")
DOWNLOADS_MODEL = "/Users/namratasrinivasa/Downloads/cctvmodel.keras"
MODEL_PATH = LOCAL_MODEL if os.path.exists(LOCAL_MODEL) else DOWNLOADS_MODEL


def load_and_preprocess_image(path: str) -> np.ndarray:
    img = Image.open(path).convert("RGB")
    img = img.resize((128, 128), Image.Resampling.BILINEAR)
    arr = np.array(img, dtype=np.float32)
    # MobileNetV2 normalization [-1, 1]
    return (arr / 127.5) - 1.0


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detect_threat.py <image_or_folder_or_list_of_frames>")
        print("Example: python3 detect_threat.py sample_frame.jpg")
        sys.exit(1)

    inputs = sys.argv[1:]
    image_paths: List[str] = []

    for item in inputs:
        if os.path.isdir(item):
            found = sorted(
                glob.glob(os.path.join(item, "*.jpg"))
                + glob.glob(os.path.join(item, "*.png"))
                + glob.glob(os.path.join(item, "*.jpeg"))
            )
            image_paths.extend(found)
        elif os.path.isfile(item):
            image_paths.append(item)

    if not image_paths:
        print("[-] No image files found.")
        sys.exit(1)

    print(f"[*] Found {len(image_paths)} input frames.")
    frames = [load_and_preprocess_image(p) for p in image_paths]

    # Sample exactly 15 frames
    if len(frames) == 15:
        selected = frames
    elif len(frames) < 15:
        indices = np.linspace(0, len(frames) - 1, 15).round().astype(int)
        selected = [frames[i] for i in indices]
    else:
        indices = np.linspace(0, len(frames) - 1, 15).round().astype(int)
        selected = [frames[i] for i in indices]

    batch = np.expand_dims(np.stack(selected, axis=0), axis=0)

    print(f"[*] Loading model from {MODEL_PATH}...")
    model = keras.models.load_model(MODEL_PATH)
    
    print("[*] Running inference...")
    pred = model.predict(batch, verbose=0)
    score = float(pred[0][0])

    is_threat = score >= 0.5
    confidence = score if is_threat else (1.0 - score)

    print("\n" + "=" * 50)
    print(f"MODEL RESULT: {'⚠️ THREAT DETECTED' if is_threat else '✅ NORMAL / SECURE'}")
    print(f"Confidence:   {confidence * 100:.2f}%")
    print(f"Raw Sigmoid:  {score:.4f}")
    print(f"Frames:       15 frames (128x128x3)")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
