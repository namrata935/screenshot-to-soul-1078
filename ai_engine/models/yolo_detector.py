import os
import logging
from typing import List, Dict, Any
import numpy as np
import torch
from ultralytics import YOLO

logger = logging.getLogger(__name__)

class YOLODetector:
    """
    YOLOv8 object detector optimized for CCTV surveillance.
    Detects persons, bags, backpacks, cell phones, laptops, and scene objects.
    """
    
    def __init__(self, model_path: str = 'yolov8n.pt', device: str = None):
        if device is None:
            if torch.cuda.is_available():
                device = 'cuda:0'
            elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                device = 'mps'
            else:
                device = 'cpu'
        
        self.device = device
        self.model_path = model_path
        
        try:
            logger.info(f"Loading YOLO model from {model_path} on {device}...")
            self.model = YOLO(model_path)
            self.model.to(device)
            logger.info(f"✅ YOLO loaded successfully on {device}")
        except Exception as e:
            logger.warning(f"Failed to load YOLO on {device}: {e}. Retrying on cpu...")
            self.device = 'cpu'
            self.model = YOLO(model_path)
            self.model.to('cpu')
            logger.info("✅ YOLO loaded on CPU fallback")

    def predict(self, frame: np.ndarray, conf: float = 0.35, iou: float = 0.45) -> List[Dict[str, Any]]:
        """
        Run object detection on an RGB or BGR numpy frame.
        Returns list of dicts: {'bbox': [x1, y1, x2, y2], 'conf': float, 'class': int, 'class_name': str}
        """
        try:
            results = self.model(
                frame,
                device=self.device,
                conf=conf,
                iou=iou,
                verbose=False,
                stream=False
            )
            
            detections = []
            for r in results:
                for box in r.boxes:
                    bbox = [float(v) for v in box.xyxy[0].cpu().numpy().tolist()]
                    confidence = float(box.conf[0])
                    class_id = int(box.cls[0])
                    class_name = str(self.model.names.get(class_id, f"obj_{class_id}"))
                    
                    detections.append({
                        'bbox': bbox,
                        'conf': confidence,
                        'class': class_id,
                        'class_name': class_name
                    })
            
            return detections
        except Exception as e:
            logger.error(f"YOLO detection error: {e}")
            return []

