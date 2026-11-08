from collections import defaultdict, deque
import numpy as np
import time
import logging
from typing import List, Dict, Any, Tuple
from ai_engine.models.pose_estimator import PoseEstimator

logger = logging.getLogger(__name__)

MATCH_RADIUS_NORMAL  = 140
TRACK_MAX_AGE        = 8
MIN_CONF_POSE        = 0.25
MIN_KP_FALL          = 13
MIN_HISTORY_ATTACK   = 3
MIN_HISTORY_FALL     = 4
PROX_VIOLENCE_FRAMES = 3


class IncidentDetector:
    """
    Unified CCTV Threat Incident Detector:
    - Attack / strike / physical altercation
    - Fall detection
    - Proximity aggression / violence
    - Restricted perimeter intrusion
    - Virtual tripwire crossing
    - Stationary object theft
    """

    def __init__(self, camera_id: str = "camera_1", alert_cooldown: float = 2.0):
        self.camera_id = camera_id
        self.alert_cooldown = alert_cooldown
        self.last_alert_time = {}

        self.person_tracks = {}
        self.person_id_counter = 0

        self.object_tracks = {}
        self.object_missing_frames = defaultdict(int)
        self.object_stationary_frames = defaultdict(int)

        self.violence_pairs = defaultdict(int)

        # Restricted zones and tripwires are empty by default unless explicitly configured
        # This prevents normal walking in the frame center from being misclassified as perimeter breach
        self.restricted_zones = []
        self.virtual_lines = []
        self.intrusion_memory = set()

    def analyze_frame(
        self,
        detections: List[Dict[str, Any]],
        poses: List[Dict[str, Any]],
        frame: np.ndarray,
        frame_number: int,
        current_time: float = None
    ) -> List[Dict[str, Any]]:
        current_time = current_time or time.time()
        incidents = []

        tracked_people = self._update_person_tracking(poses)

        incidents += self._detect_attack(tracked_people, current_time)
        incidents += self._detect_fall(tracked_people, frame, current_time)
        incidents += self._detect_intrusion(tracked_people, current_time)
        incidents += self._detect_proximity_violence(tracked_people, current_time)
        incidents += self._detect_theft(detections, current_time)

        return self._apply_cooldown(incidents, current_time)

    def _update_person_tracking(self, poses: List[Dict[str, Any]]):
        for pid in list(self.person_tracks.keys()):
            self.person_tracks[pid]["age"] += 1
            if self.person_tracks[pid]["age"] > TRACK_MAX_AGE:
                del self.person_tracks[pid]

        matched_pids = set()

        for pose in poses:
            if pose.get("conf", 0) < MIN_CONF_POSE:
                continue

            kps = pose.get("keypoints", [])
            bbox = pose.get("bbox")
            if not bbox or len(bbox) != 4:
                continue

            center = self._center(bbox)
            best_pid, best_dist = None, MATCH_RADIUS_NORMAL

            for pid, track in self.person_tracks.items():
                if pid in matched_pids:
                    continue
                d = self._distance(center, track["center"])
                if d < best_dist:
                    best_dist, best_pid = d, pid

            if best_pid is None:
                best_pid = self.person_id_counter
                self.person_id_counter += 1
                self.person_tracks[best_pid] = {
                    "history": deque(maxlen=20),
                    "center": center,
                    "age": 0,
                }

            matched_pids.add(best_pid)
            self.person_tracks[best_pid]["center"] = center
            self.person_tracks[best_pid]["age"] = 0
            self.person_tracks[best_pid]["history"].append({
                "center": center,
                "bbox": bbox,
                "keypoints": kps,
                "timestamp": time.time()
            })

        return [(pid, list(track["history"])) for pid, track in self.person_tracks.items()]

    def _detect_attack(self, tracked_people, current_time: float):
        incidents = []
        # An interpersonal physical strike requires a target person in proximity
        if len(tracked_people) < 2:
            return incidents

        for pid, history in tracked_people:
            if len(history) < MIN_HISTORY_ATTACK:
                continue

            # Check if there is another tracked person within reach (<= 180 pixels)
            curr_center = history[-1]["center"]
            has_nearby_target = any(
                other_pid != pid and self._distance(curr_center, other_track[-1]["center"]) < 180
                for other_pid, other_track in tracked_people
                if other_track
            )
            if not has_nearby_target:
                continue

            curr_kps = history[-1].get("keypoints", [])
            prev_kps = history[-MIN_HISTORY_ATTACK].get("keypoints", [])

            # Check wrist keypoints (indices 15=left wrist, 16=right wrist)
            if len(curr_kps) > 16 and len(prev_kps) > 16:
                for wrist_idx, shoulder_idx in [(15, 11), (16, 12)]:
                    c_wrist = curr_kps[wrist_idx]
                    p_wrist = prev_kps[wrist_idx]
                    shoulder = curr_kps[shoulder_idx]

                    if c_wrist[2] > 0.3 and p_wrist[2] > 0.3 and shoulder[2] > 0.3:
                        dx = c_wrist[0] - p_wrist[0]
                        dy = c_wrist[1] - p_wrist[1]
                        wrist_speed = np.sqrt(dx**2 + dy**2)

                        # Fast forward arm strike extension toward nearby target
                        if wrist_speed > 55:
                            incidents.append({
                                "type": "attack_detected",
                                "severity": "high",
                                "severityScore": 84,
                                "confidence": 0.85,
                                "description": "Rapid physical strike/punch trajectory detected.",
                                "camera_id": self.camera_id,
                                "timestamp": current_time,
                                "bbox": [float(v) for v in history[-1]["bbox"]],
                            })
                            break
        return incidents

    def _detect_fall(self, tracked_people, frame: np.ndarray, current_time: float):
        incidents = []
        frame_h = frame.shape[0] if frame is not None else 480

        for pid, history in tracked_people:
            if len(history) < MIN_HISTORY_FALL:
                continue

            first_kps = history[0].get("keypoints", [])
            last_kps = history[-1].get("keypoints", [])

            # Hips (23, 24) and Shoulders (11, 12)
            if len(first_kps) > 24 and len(last_kps) > 24:
                f_hip_y = (first_kps[23][1] + first_kps[24][1]) / 2.0
                l_hip_y = (last_kps[23][1] + last_kps[24][1]) / 2.0

                drop = l_hip_y - f_hip_y  # Positive downwards in image coordinates
                bbox = history[-1]["bbox"]
                w = max(1.0, bbox[2] - bbox[0])
                h = max(1.0, bbox[3] - bbox[1])

                # Torso inclination: shoulders vs hips horizontal
                sh_x = (last_kps[11][0] + last_kps[12][0]) / 2.0
                sh_y = (last_kps[11][1] + last_kps[12][1]) / 2.0
                hip_x = (last_kps[23][0] + last_kps[24][0]) / 2.0
                hip_y = (last_kps[23][1] + last_kps[24][1]) / 2.0

                dx = abs(sh_x - hip_x)
                dy = abs(sh_y - hip_y)
                is_horizontal = dx > dy * 1.2 or (h / w < 0.75)

                if drop > frame_h * 0.12 and is_horizontal:
                    incidents.append({
                        "type": "fall_detected",
                        "severity": "critical",
                        "severityScore": 90,
                        "confidence": 0.89,
                        "description": "Rapid downward drop followed by horizontal body orientation.",
                        "camera_id": self.camera_id,
                        "timestamp": current_time,
                        "bbox": [float(v) for v in bbox],
                    })
        return incidents

    def _detect_proximity_violence(self, tracked_people, current_time: float):
        incidents = []
        n = len(tracked_people)
        for i in range(n):
            for j in range(i + 1, n):
                id1, hist1 = tracked_people[i]
                id2, hist2 = tracked_people[j]
                if not hist1 or not hist2:
                    continue

                d = self._distance(hist1[-1]["center"], hist2[-1]["center"])
                key = (min(id1, id2), max(id1, id2))

                # Measure movement speeds and directional alignment to differentiate peaceful proximity from active struggle
                speed1 = self._distance(hist1[-1]["center"], hist1[-2]["center"]) if len(hist1) >= 2 else 0.0
                speed2 = self._distance(hist2[-1]["center"], hist2[-2]["center"]) if len(hist2) >= 2 else 0.0

                if len(hist1) >= 2 and len(hist2) >= 2:
                    v1 = (hist1[-1]["center"][0] - hist1[-2]["center"][0], hist1[-1]["center"][1] - hist1[-2]["center"][1])
                    v2 = (hist2[-1]["center"][0] - hist2[-2]["center"][0], hist2[-1]["center"][1] - hist2[-2]["center"][1])
                    mag1 = np.sqrt(v1[0] ** 2 + v1[1] ** 2)
                    mag2 = np.sqrt(v2[0] ** 2 + v2[1] ** 2)
                    rel_speed = np.sqrt((v1[0] - v2[0]) ** 2 + (v1[1] - v2[1]) ** 2)
                    dot = v1[0] * v2[0] + v1[1] * v2[1]
                    cos_sim = dot / (mag1 * mag2) if (mag1 > 2.0 and mag2 > 2.0) else 0.0

                    prev_d = self._distance(hist1[-2]["center"], hist2[-2]["center"])
                    dist_change = abs(d - prev_d)

                    is_parallel_peaceful = (cos_sim > 0.6 and dist_change < 15.0 and rel_speed < 18.0)
                    has_struggle_motion = (not is_parallel_peaceful) and (
                        rel_speed > 25.0 or dist_change > 22.0 or ((mag1 + mag2) > 35.0 and cos_sim < 0.2)
                    )
                else:
                    has_struggle_motion = False

                # Physical confrontation requires close proximity AND aggressive struggle motion
                if d < 100 and has_struggle_motion:
                    self.violence_pairs[key] += 1
                else:
                    self.violence_pairs[key] = max(0, self.violence_pairs[key] - 1)

                if self.violence_pairs[key] >= PROX_VIOLENCE_FRAMES:
                    combined_bbox = [
                        min(hist1[-1]["bbox"][0], hist2[-1]["bbox"][0]),
                        min(hist1[-1]["bbox"][1], hist2[-1]["bbox"][1]),
                        max(hist1[-1]["bbox"][2], hist2[-1]["bbox"][2]),
                        max(hist1[-1]["bbox"][3], hist2[-1]["bbox"][3])
                    ]
                    incidents.append({
                        "type": "violence_detected",
                        "severity": "high",
                        "severityScore": 88,
                        "confidence": 0.86,
                        "description": "Sustained close-range physical altercation / confrontation detected.",
                        "camera_id": self.camera_id,
                        "timestamp": current_time,
                        "bbox": [float(v) for v in combined_bbox],
                    })
                    self.violence_pairs[key] = 0
        return incidents

    def _detect_intrusion(self, tracked_people, current_time: float):
        incidents = []
        for pid, history in tracked_people:
            if len(history) < 2:
                continue

            center = history[-1]["center"]
            prev_center = history[-2]["center"]

            for (x1, y1, x2, y2) in self.restricted_zones:
                if x1 <= center[0] <= x2 and y1 <= center[1] <= y2:
                    if pid not in self.intrusion_memory:
                        self.intrusion_memory.add(pid)
                        incidents.append({
                            "type": "intrusion_detected",
                            "severity": "high",
                            "severityScore": 79,
                            "confidence": 0.91,
                            "description": "Unauthorized subject entered restricted perimeter zone.",
                            "camera_id": self.camera_id,
                            "timestamp": current_time,
                            "bbox": [float(v) for v in history[-1]["bbox"]],
                        })

            for line in self.virtual_lines:
                (lx1, _), (lx2, _) = line
                if prev_center[0] < lx1 and center[0] >= lx1:
                    incidents.append({
                        "type": "line_crossing",
                        "severity": "medium",
                        "severityScore": 58,
                        "confidence": 0.84,
                        "description": "Subject crossed virtual security demarcation line.",
                        "camera_id": self.camera_id,
                        "timestamp": current_time,
                        "bbox": [float(v) for v in history[-1]["bbox"]],
                    })
        return incidents

    def _detect_theft(self, detections: List[Dict[str, Any]], current_time: float):
        incidents = []
        valuable_classes = {"backpack", "handbag", "suitcase", "laptop", "cell phone"}
        visible_ids = set()

        for det in detections:
            if det.get("class_name") in valuable_classes and det.get("conf", 0) > 0.35:
                bbox = det["bbox"]
                obj_id = f"{det['class_name']}_{int(bbox[0]//40)}_{int(bbox[1]//40)}"
                visible_ids.add(obj_id)
                center = self._center(bbox)

                if obj_id in self.object_tracks:
                    mv = self._distance(center, self.object_tracks[obj_id])
                    if mv < 15:
                        self.object_stationary_frames[obj_id] += 1
                    else:
                        self.object_stationary_frames[obj_id] = 0

                self.object_tracks[obj_id] = center
                self.object_missing_frames[obj_id] = 0

        for obj_id in list(self.object_tracks.keys()):
            if obj_id not in visible_ids:
                self.object_missing_frames[obj_id] += 1
                if self.object_stationary_frames[obj_id] > 25 and self.object_missing_frames[obj_id] > 5:
                    incidents.append({
                        "type": "theft_detected",
                        "severity": "high",
                        "severityScore": 82,
                        "confidence": 0.87,
                        "description": f"Valuable asset ({obj_id.split('_')[0]}) was removed from monitored station.",
                        "camera_id": self.camera_id,
                        "timestamp": current_time,
                    })
                    del self.object_tracks[obj_id]

        return incidents

    def _distance(self, p1, p2) -> float:
        return float(np.sqrt((p1[0] - p2[0])**2 + (p1[1] - p2[1])**2))

    def _center(self, bbox: List[float]):
        return ((bbox[0] + bbox[2]) / 2.0, (bbox[1] + bbox[3]) / 2.0)

    def _apply_cooldown(self, incidents: List[Dict[str, Any]], current_time: float):
        out = []
        for inc in incidents:
            t = inc["type"]
            if t not in self.last_alert_time or (current_time - self.last_alert_time[t] > self.alert_cooldown):
                self.last_alert_time[t] = current_time
                out.append(inc)
        return out

    def reset(self):
        self.person_tracks.clear()
        self.object_tracks.clear()
        self.object_missing_frames.clear()
        self.object_stationary_frames.clear()
        self.violence_pairs.clear()
        self.last_alert_time.clear()
        self.intrusion_memory.clear()

