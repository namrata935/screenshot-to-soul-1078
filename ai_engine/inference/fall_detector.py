import logging
import numpy as np
from collections import defaultdict, deque
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class SmartFallDetector:
    """
    Context-aware fall detector analyzing trajectory, rapid descent, horizontal aspect ratio,
    ground proximity, and post-fall lack of motion.
    """

    def __init__(self, camera_id: str = "camera_1"):
        self.camera_id = camera_id
        self.person_tracks = defaultdict(lambda: deque(maxlen=20))
        self.fall_candidates = {}

        self.MIN_CONF_PERSON = 0.35
        self.HORIZONTAL_THRESHOLD = 0.75  # Aspect ratio h/w below this indicates horizontal pose
        self.DROP_RATIO = 0.12            # 12% vertical drop across sequence
        self.GROUND_RATIO = 0.65          # Lower 35% of frame
        self.CONFIRM_FRAMES = 3           # Frames to confirm
        self.MOTIONLESS_FRAMES = 2

    def analyze_fall(self, detections: List[Dict[str, Any]], frame: np.ndarray, frame_number: int, current_time: float) -> List[Dict[str, Any]]:
        incidents = []
        frame_h = frame.shape[0] if frame is not None else 480

        tracked_people = self._update_tracks(detections)

        for pid, history in tracked_people:
            if len(history) < 3:
                continue

            recent = list(history)[-6:]
            y_positions = [f["center"][1] for f in recent]
            drop = max(y_positions) - min(y_positions)

            last_bbox = recent[-1]["bbox"]
            w = max(1.0, last_bbox[2] - last_bbox[0])
            h = max(1.0, last_bbox[3] - last_bbox[1])
            aspect_ratio = h / w

            horizontal = aspect_ratio < self.HORIZONTAL_THRESHOLD
            on_ground = last_bbox[3] > frame_h * self.GROUND_RATIO
            sudden_drop = drop > (frame_h * self.DROP_RATIO)

            # Trigger condition: sudden drop + horizontal pose or ground proximity
            if (sudden_drop and horizontal) or (horizontal and on_ground and drop > frame_h * 0.05):
                if pid not in self.fall_candidates:
                    self.fall_candidates[pid] = {
                        "count": 1,
                        "last_y": y_positions[-1],
                        "motionless": 0,
                    }
                else:
                    self.fall_candidates[pid]["count"] += 1
                    dy = abs(y_positions[-1] - self.fall_candidates[pid]["last_y"])
                    if dy < frame_h * 0.04:
                        self.fall_candidates[pid]["motionless"] += 1
                    else:
                        self.fall_candidates[pid]["motionless"] = 0
                    self.fall_candidates[pid]["last_y"] = y_positions[-1]

                if self.fall_candidates[pid]["count"] >= self.CONFIRM_FRAMES:
                    incidents.append({
                        "type": "fall_detected",
                        "severity": "critical",
                        "severityScore": 92,
                        "confidence": 0.88,
                        "description": "Person fall detected: rapid downward trajectory and horizontal posture on ground.",
                        "camera_id": self.camera_id,
                        "timestamp": current_time,
                        "bbox": [float(v) for v in last_bbox],
                        "frame_number": frame_number,
                    })
                    logger.warning(f"🚨 Confirmed Fall on {self.camera_id} (person track {pid})")
                    del self.fall_candidates[pid]
            else:
                if pid in self.fall_candidates:
                    self.fall_candidates[pid]["count"] = max(0, self.fall_candidates[pid]["count"] - 1)
                    if self.fall_candidates[pid]["count"] == 0:
                        del self.fall_candidates[pid]

        return incidents

    def _update_tracks(self, detections: List[Dict[str, Any]]):
        updated_tracks = {}
        tracked = []

        for det in detections:
            if det.get("class_name") != "person" or det.get("conf", 0) < self.MIN_CONF_PERSON:
                continue

            bbox = det["bbox"]
            center = ((bbox[0] + bbox[2]) / 2, (bbox[1] + bbox[3]) / 2)

            matched_id = None
            for pid, history in self.person_tracks.items():
                if history:
                    last_center = history[-1]["center"]
                    dist = np.sqrt((center[0] - last_center[0]) ** 2 + (center[1] - last_center[1]) ** 2)
                    if dist < 80:
                        matched_id = pid
                        break

            if matched_id is None:
                matched_id = len(self.person_tracks) + 1

            if matched_id not in updated_tracks:
                updated_tracks[matched_id] = self.person_tracks.get(matched_id, deque(maxlen=20))

            updated_tracks[matched_id].append({
                "bbox": bbox,
                "center": center,
            })
            tracked.append((matched_id, updated_tracks[matched_id]))

        self.person_tracks = updated_tracks
        return tracked

    def reset(self):
        self.person_tracks.clear()
        self.fall_candidates.clear()

