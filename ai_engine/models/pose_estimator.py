import logging
from typing import List, Dict, Any
import numpy as np
import cv2
import mediapipe as mp

logger = logging.getLogger(__name__)

class PoseEstimator:
    """
    Human pose estimation using MediaPipe with skeleton rendering and feature extraction.
    """

    def __init__(self, use_mediapipe: bool = True, min_detection_confidence: float = 0.4):
        self.use_mediapipe = use_mediapipe
        self.pose = None

        if use_mediapipe:
            try:
                self.mp_pose = mp.solutions.pose
                self.pose = self.mp_pose.Pose(
                    static_image_mode=False,
                    model_complexity=1,
                    min_detection_confidence=min_detection_confidence,
                    min_tracking_confidence=0.5,
                )
                self.mp_draw = mp.solutions.drawing_utils
                logger.info("✅ MediaPipe Pose initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize MediaPipe Pose: {e}")
                self.use_mediapipe = False

    def estimate(self, frame: np.ndarray) -> List[Dict[str, Any]]:
        if self.use_mediapipe and self.pose is not None:
            return self._estimate_mediapipe(frame)
        return self._estimate_fallback(frame)

    def _estimate_mediapipe(self, frame: np.ndarray) -> List[Dict[str, Any]]:
        try:
            # MediaPipe expects RGB
            if len(frame.shape) == 3 and frame.shape[2] == 3:
                # If frame is BGR (standard OpenCV) convert to RGB, otherwise check
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            else:
                rgb_frame = frame

            results = self.pose.process(rgb_frame)
            poses = []

            if results and results.pose_landmarks:
                frame_h, frame_w = frame.shape[:2]
                keypoints = []
                confidences = []

                for lm in results.pose_landmarks.landmark:
                    x = float(lm.x * frame_w)
                    y = float(lm.y * frame_h)
                    confidence = float(lm.visibility)
                    keypoints.append((x, y, confidence))
                    confidences.append(confidence)

                avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

                # Derive pixel bounding box from visible landmarks
                visible_pts = [(kp[0], kp[1]) for kp in keypoints if kp[2] > 0.25]
                if visible_pts:
                    xs = [p[0] for p in visible_pts]
                    ys = [p[1] for p in visible_pts]
                    pad_x = max(10, (max(xs) - min(xs)) * 0.08)
                    pad_y = max(10, (max(ys) - min(ys)) * 0.08)
                    x1 = max(0.0, min(xs) - pad_x)
                    y1 = max(0.0, min(ys) - pad_y)
                    x2 = min(float(frame_w), max(xs) + pad_x)
                    y2 = min(float(frame_h), max(ys) + pad_y)
                    bbox = [x1, y1, x2, y2]
                else:
                    bbox = [0.0, 0.0, float(frame_w), float(frame_h)]

                poses.append({
                    "keypoints": keypoints,
                    "conf": avg_conf,
                    "num_keypoints": len(keypoints),
                    "bbox": bbox
                })

            return poses
        except Exception as e:
            logger.error(f"MediaPipe pose estimation error: {e}")
            return []

    def _estimate_fallback(self, frame: np.ndarray) -> List[Dict[str, Any]]:
        h, w = frame.shape[:2]
        return [{
            "keypoints": [(w / 2, h / 2, 0.5)],
            "conf": 0.5,
            "num_keypoints": 1,
            "bbox": [w * 0.2, h * 0.1, w * 0.8, h * 0.9],
        }]

    def draw_pose(self, frame: np.ndarray, poses: List[Dict[str, Any]]) -> np.ndarray:
        """
        Draw skeleton joints and connections on frame (in-place or returned copy).
        """
        output = frame.copy()
        connections = [
            (11, 12), (11, 13), (13, 15), (12, 14), (14, 16),
            (11, 23), (12, 24), (23, 24), (23, 25), (25, 27),
            (24, 26), (26, 28), (15, 17), (15, 19), (15, 21),
            (16, 18), (16, 20), (16, 22), (27, 29), (27, 31),
            (28, 30), (28, 32)
        ]

        for pose in poses:
            kps = pose.get("keypoints", [])
            for pt in kps:
                if len(pt) >= 3 and pt[2] > 0.3:
                    cv2.circle(output, (int(pt[0]), int(pt[1])), 4, (0, 255, 136), -1)

            for (i, j) in connections:
                if i < len(kps) and j < len(kps):
                    p1, p2 = kps[i], kps[j]
                    if len(p1) >= 3 and len(p2) >= 3 and p1[2] > 0.3 and p2[2] > 0.3:
                        cv2.line(output, (int(p1[0]), int(p1[1])), (int(p2[0]), int(p2[1])), (0, 220, 255), 2)

        return output

    def __del__(self):
        if hasattr(self, "pose") and self.pose is not None:
            try:
                self.pose.close()
            except:
                pass

