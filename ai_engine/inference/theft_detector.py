import os
import time
import logging
from collections import defaultdict
from typing import List, Dict, Any
import numpy as np

logger = logging.getLogger(__name__)

class SmartTheftDetector:
    """
    CCTV Theft and Abandoned Valuables detector.
    Monitors valuables (backpack, handbag, suitcase, laptop, cell phone) and detects
    suspicious non-owner interactions or unauthorized object removal.
    """

    def __init__(self, camera_id: str = "camera_1"):
        self.camera_id = camera_id
        self.object_owners = {}
        self.object_positions = {}
        self.object_stationary_frames = defaultdict(int)
        self.object_missing_frames = defaultdict(int)
        self.theft_candidates = defaultdict(lambda: {"frames": 0, "score": 0.0, "last_frame": 0})

        self.VALUABLE_OBJECTS = [
            "backpack", "handbag", "suitcase",
            "laptop", "cell phone", "book", "handbag", "briefcase"
        ]
        self.MIN_CONF_PERSON = 0.35
        self.MIN_CONF_VALUABLE = 0.30

    def analyze_theft(self, detections: List[Dict[str, Any]], frame: np.ndarray, frame_number: int, current_time: float) -> List[Dict[str, Any]]:
        incidents = []

        persons = [
            d for d in detections
            if d.get("class_name") == "person" and d.get("conf", 0) > self.MIN_CONF_PERSON
        ]
        valuables = [
            d for d in detections
            if d.get("class_name") in self.VALUABLE_OBJECTS and d.get("conf", 0) > self.MIN_CONF_VALUABLE
        ]

        visible_ids = set()

        # Update visible objects
        for val in valuables:
            obj_id = self._get_object_id(val)
            visible_ids.add(obj_id)
            center = self._get_bbox_center(val["bbox"])

            if obj_id in self.object_positions:
                movement = self._euclidean(center, self.object_positions[obj_id])
                if movement < 15:
                    self.object_stationary_frames[obj_id] += 1
                else:
                    self.object_stationary_frames[obj_id] = 0

            self.object_positions[obj_id] = center
            self.object_missing_frames[obj_id] = 0
            self._update_ownership(obj_id, val, persons)

        # Detect missing objects (unattended object genuinely stationary and suddenly removed by non-owner)
        for obj_id in list(self.object_positions.keys()):
            if obj_id not in visible_ids:
                self.object_missing_frames[obj_id] += 1
                if self.object_stationary_frames[obj_id] >= 25 and self.object_missing_frames[obj_id] >= 6:
                    severity = "critical" if self.object_owners.get(obj_id) is not None else "high"
                    incidents.append({
                        "type": "theft_detected",
                        "severity": severity,
                        "severityScore": 86 if severity == "critical" else 75,
                        "confidence": 0.88,
                        "description": f"Valuable item ({obj_id.split('_')[0]}) was removed from monitored surveillance zone.",
                        "camera_id": self.camera_id,
                        "timestamp": current_time,
                        "object_id": obj_id,
                    })
                    logger.warning(f"🚨 Theft incident detected: {obj_id} on {self.camera_id}")
                    self._clear_object(obj_id)

        # Suspicious proximity check
        for val in valuables:
            obj_id = self._get_object_id(val)
            for person in persons:
                dist = self._calculate_distance(person["bbox"], val["bbox"])
                if dist < 80:
                    is_owner = self.object_owners.get(obj_id) == self._get_person_id(person)
                    if not is_owner:
                        key = f"{obj_id}_{self._get_person_id(person)}"
                        self.theft_candidates[key]["frames"] += 1
                        self.theft_candidates[key]["last_frame"] = frame_number

                        if self.theft_candidates[key]["frames"] >= 3:
                            incidents.append({
                                "type": "suspicious_proximity",
                                "severity": "medium",
                                "severityScore": 64,
                                "confidence": 0.78,
                                "description": f"Unrecognized individual loitering within arm's reach of unattended {val.get('class_name')}.",
                                "camera_id": self.camera_id,
                                "timestamp": current_time,
                                "object_id": obj_id,
                                "bbox": [float(v) for v in val["bbox"]],
                            })
                            del self.theft_candidates[key]

        return incidents

    def _update_ownership(self, obj_id: str, val: Dict, persons: List[Dict]):
        closest_person = None
        min_dist = float("inf")
        for p in persons:
            d = self._calculate_distance(p["bbox"], val["bbox"])
            if d < min_dist:
                min_dist = d
                closest_person = p
        if closest_person and min_dist < 90:
            pid = self._get_person_id(closest_person)
            if obj_id not in self.object_owners:
                self.object_owners[obj_id] = pid

    def _get_object_id(self, valuable: Dict) -> str:
        bbox = valuable["bbox"]
        return f"{valuable.get('class_name', 'item')}_{int(bbox[0] // 50)}_{int(bbox[1] // 50)}"

    def _get_person_id(self, person: Dict) -> str:
        bbox = person["bbox"]
        return f"p_{int(bbox[0] // 50)}_{int(bbox[1] // 50)}"

    def _get_bbox_center(self, bbox: List[float]):
        return ((bbox[0] + bbox[2]) / 2, (bbox[1] + bbox[3]) / 2)

    def _calculate_distance(self, bbox1: List[float], bbox2: List[float]) -> float:
        c1 = self._get_bbox_center(bbox1)
        c2 = self._get_bbox_center(bbox2)
        return self._euclidean(c1, c2)

    def _euclidean(self, p1, p2) -> float:
        return float(np.sqrt((p1[0] - p2[0]) ** 2 + (p1[1] - p2[1]) ** 2))

    def _clear_object(self, obj_id: str):
        self.object_owners.pop(obj_id, None)
        self.object_positions.pop(obj_id, None)
        self.object_stationary_frames.pop(obj_id, None)
        self.object_missing_frames.pop(obj_id, None)

    def reset(self):
        self.object_owners.clear()
        self.object_positions.clear()
        self.object_stationary_frames.clear()
        self.object_missing_frames.clear()
        self.theft_candidates.clear()

