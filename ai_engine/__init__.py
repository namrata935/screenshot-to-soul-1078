"""
AI CCTV Multi-Detection Engine
Integrated from ai-cctv-threat-detection:
- YOLOv8 Object Detection (Ultralytics)
- MediaPipe Pose Estimation & Skeleton Tracking
- Context-Aware Smart Fall Detector
- Smart Theft & Valuables Detector
- Multi-Threat Incident Detector (Attacks, Falls, Intrusions, Thefts, Violence)
- Severity Risk Scorer
- TimeDistributed + LSTM Deep Learning Violence Classifier (cctvmodel.keras)
- Model Training & Evaluation Suite (Behavior, Pose, YOLO, Metrics)
"""

from . import models
from . import inference
from . import utils
from . import data
from . import training

__version__ = "2.1.0"
__all__ = ["models", "inference", "utils", "data", "training"]

