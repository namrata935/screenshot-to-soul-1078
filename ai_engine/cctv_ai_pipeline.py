import os
import io
import time
import base64
import logging
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from scipy.optimize import linear_sum_assignment
from PIL import Image
import cv2

from ai_engine.models.yolo_detector import YOLODetector
from ai_engine.models.pose_estimator import PoseEstimator
from ai_engine.models.tracker import ByteTracker
from ai_engine.inference.incident_detector import IncidentDetector
from ai_engine.inference.fall_detector import SmartFallDetector
from ai_engine.inference.theft_detector import SmartTheftDetector
from ai_engine.inference.severity_scorer import score_severity
from ai_engine.utils.frame_validator import FrameValidator

logger = logging.getLogger(__name__)

class CCTVThreatEngine:
    """
    Unified AI Surveillance Engine combining:
    1. YOLOv8 object detection & ByteTracker
    2. MediaPipe Pose estimation & skeleton rendering
    3. Context-aware Incident Detectors (Fall, Theft, Violence, Intrusion)
    4. Multi-factor Severity Risk Scorer
    5. Keras TimeDistributed+LSTM deep violence sequence model
    """

    def __init__(self, keras_model_path: str = None, yolo_model_path: str = "yolov8n.pt"):
        self.frame_count = 0
        self.validator = FrameValidator()

        # 1. Initialize YOLOv8 Detector
        logger.info("[*] Initializing YOLOv8 detector...")
        try:
            self.yolo = YOLODetector(yolo_model_path)
        except Exception as e:
            logger.error(f"[!] Failed to initialize YOLO: {e}")
            self.yolo = None

        # 2. Initialize MediaPipe Pose Estimator
        logger.info("[*] Initializing MediaPipe Pose estimator...")
        try:
            self.pose_estimator = PoseEstimator(use_mediapipe=True)
        except Exception as e:
            logger.error(f"[!] Failed to initialize PoseEstimator: {e}")
            self.pose_estimator = None

        # 3. Object & Person Tracker
        self.tracker = ByteTracker(max_age=20, min_hits=2)

        # 4. Incident Detectors
        self.incident_detector = IncidentDetector(camera_id="cam_main")
        self.fall_detector = SmartFallDetector(camera_id="cam_main")
        self.theft_detector = SmartTheftDetector(camera_id="cam_main")

        # 5. Keras LSTM Sequence Model
        self.keras_model = None
        self.keras_model_path = keras_model_path
        if keras_model_path and os.path.exists(keras_model_path):
            self._load_keras_model(keras_model_path)

        logger.info("✅ CCTV Threat Engine initialized successfully!")

    def _load_keras_model(self, model_path: str):
        try:
            import keras
            logger.info(f"[*] Loading Keras LSTM model from {model_path}...")
            self.keras_model = keras.models.load_model(model_path)
            # Warm up
            dummy = np.zeros((1, 15, 128, 128, 3), dtype=np.float32)
            _ = self.keras_model.predict(dummy, verbose=0)
            logger.info("✅ Keras sequence model loaded and warmed up.")
        except Exception as e:
            logger.error(f"[!] Error loading Keras model: {e}")
            self.keras_model = None

    def analyze_frame(
        self,
        frame: np.ndarray,
        return_annotated: bool = True,
        conf_threshold: float = 0.35
    ) -> Dict[str, Any]:
        """
        Analyze a single frame with YOLO, MediaPipe Pose, and incident detectors.
        """
        t_start = time.time()
        self.frame_count += 1
        now = time.time()

        # Validate
        is_valid, msg, _ = self.validator.validate_frame(frame, self.frame_count)
        if not is_valid:
            proc_ms = round((time.time() - t_start) * 1000)
            return {
                "status": "warning",
                "message": msg,
                "objects": [],
                "poses": [],
                "incidents": [],
                "processingTimeMs": proc_ms,
                "hasIncident": False,
                "annotatedFrame": None
            }

        # 1. Object Detection
        detections = []
        if self.yolo:
            detections = self.yolo.predict(frame, conf=conf_threshold)

        # 2. Tracking
        tracked_objects = self.tracker.update(detections) if detections else []

        # 3. Pose Estimation
        poses = []
        if self.pose_estimator:
            poses = self.pose_estimator.estimate(frame)

        # 4. Incident Detection
        incidents = []
        if self.incident_detector:
            incidents += self.incident_detector.analyze_frame(
                detections=detections,
                poses=poses,
                frame=frame,
                frame_number=self.frame_count,
                current_time=now
            )

        if self.fall_detector:
            incidents += self.fall_detector.analyze_fall(
                detections=detections,
                frame=frame,
                frame_number=self.frame_count,
                current_time=now
            )

        if self.theft_detector:
            incidents += self.theft_detector.analyze_theft(
                detections=detections,
                frame=frame,
                frame_number=self.frame_count,
                current_time=now
            )

        # Score severity for each incident
        for inc in incidents:
            scored = score_severity(inc, {"num_actors": len(poses)})
            inc["severityScore"] = scored["score"]
            inc["severity"] = scored["label"].capitalize()

        # Deduplicate incidents by type within the current frame
        seen_types = set()
        unique_incidents = []
        for inc in incidents:
            if inc["type"] not in seen_types:
                seen_types.add(inc["type"])
                unique_incidents.append(inc)

        # 5. Render Visualization if requested
        annotated_b64 = None
        if return_annotated:
            annotated_frame = self.render_overlay(frame, detections, poses, unique_incidents)
            annotated_b64 = self._frame_to_base64(annotated_frame)

        proc_ms = round((time.time() - t_start) * 1000)

        return {
            "status": "success",
            "frameNumber": self.frame_count,
            "processingTimeMs": proc_ms,
            "objectsCount": len(detections),
            "objects": detections,
            "trackedCount": len(tracked_objects),
            "posesCount": len(poses),
            "poses": poses,
            "incidents": unique_incidents,
            "hasIncident": len(unique_incidents) > 0,
            "annotatedFrame": annotated_b64
        }

    @staticmethod
    def _match_boxes(prev_boxes: List[List[float]], curr_boxes: List[List[float]], max_dist: float = 200.0) -> List[Tuple[List[float], List[float]]]:
        """Globally associates person detections between adjacent frames using optimal bipartite matching."""
        if not prev_boxes or not curr_boxes:
            return []
        p_ctrs = np.array([[(b[0] + b[2]) / 2.0, (b[1] + b[3]) / 2.0] for b in prev_boxes])
        c_ctrs = np.array([[(b[0] + b[2]) / 2.0, (b[1] + b[3]) / 2.0] for b in curr_boxes])
        dists = np.linalg.norm(p_ctrs[:, None, :] - c_ctrs[None, :, :], axis=2)
        row_ind, col_ind = linear_sum_assignment(dists)
        pairs = []
        for r, c in zip(row_ind, col_ind):
            if dists[r, c] <= max_dist:
                pairs.append((prev_boxes[r], curr_boxes[c]))
        return pairs

    def analyze_sequence(
        self,
        frames: List[np.ndarray],
        threshold: float = 0.5,
        return_annotated: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze a sequence of frames (e.g. 15 frames from webcam or uploaded video):
        Runs Keras MobileNetV2+LSTM sequence model AND runs YOLO/MediaPipe incident detection
        across the sequence.
        """
        t_start = time.time()
        n = len(frames)
        if n == 0:
            return {"status": "error", "message": "No frames provided"}

        # 1. Keras LSTM Sequence Classification
        keras_result = None
        if self.keras_model:
            try:
                # Sample 15 frames and preprocess for MobileNetV2 (128x128, [-1, 1])
                indices = np.linspace(0, n - 1, 15).round().astype(int)
                sampled_for_keras = []
                for i in indices:
                    f = frames[i]
                    # Resize to 128x128 (frames are RGB numpy arrays)
                    img = Image.fromarray(f) if isinstance(f, np.ndarray) else f
                    img = img.resize((128, 128), Image.Resampling.BILINEAR)
                    arr = (np.array(img, dtype=np.float32) / 127.5) - 1.0
                    sampled_for_keras.append(arr)

                tensor = np.expand_dims(np.stack(sampled_for_keras, axis=0), axis=0)
                pred = self.keras_model.predict(tensor, verbose=0)
                raw_score = float(pred[0][0])
                is_threat = raw_score >= threshold
                confidence = raw_score if is_threat else (1.0 - raw_score)

                keras_result = {
                    "isThreat": is_threat,
                    "label": "THREAT DETECTED" if is_threat else "NORMAL / SECURE",
                    "threatType": "Physical Violence / Altercation Sequence" if is_threat else "None",
                    "confidence": round(confidence, 4),
                    "rawScore": round(raw_score, 4),
                    "threshold": threshold,
                    "model": "cctvmodel.keras"
                }
            except Exception as e:
                logger.error(f"Keras prediction error: {e}")

        # 2. Frame-by-frame analysis with YOLO + MediaPipe + Incident detection
        all_incidents = []
        last_analysis = None
        max_people = 0
        has_violent_motion = False
        frame_person_boxes = []

        for i, frame in enumerate(frames):
            analysis = self.analyze_frame(frame, return_annotated=(i == n - 1 and return_annotated))
            last_analysis = analysis
            p_boxes = [d["bbox"] for d in analysis.get("objects", []) if d.get("class_name") == "person"]
            frame_person_boxes.append(p_boxes)
            p_count = len(p_boxes)
            max_people = max(max_people, p_count, len(analysis.get("poses", [])))
            for inc in analysis.get("incidents", []):
                all_incidents.append(inc)
                if inc.get("type") in ("attack_detected", "violence_detected", "fall_detected"):
                    has_violent_motion = True

        # Check for high-velocity physical struggle / entanglement between multiple persons
        # (detects tussling/brawling even if skeletal pose estimation is partially occluded)
        if max_people >= 2 and not has_violent_motion and len(frame_person_boxes) >= 2:
            close_struggle_frames = 0
            for i in range(1, len(frame_person_boxes)):
                prev_boxes = frame_person_boxes[i - 1]
                curr_boxes = frame_person_boxes[i]
                if len(prev_boxes) >= 2 and len(curr_boxes) >= 2:
                    matched = self._match_boxes(prev_boxes, curr_boxes)
                    if len(matched) >= 2:
                        frame_has_struggle = False
                        for m_idx in range(len(matched)):
                            for n_idx in range(m_idx + 1, len(matched)):
                                p0, c0 = matched[m_idx]
                                p1, c1 = matched[n_idx]

                                c0_ctr = ((c0[0] + c0[2]) / 2.0, (c0[1] + c0[3]) / 2.0)
                                c1_ctr = ((c1[0] + c1[2]) / 2.0, (c1[1] + c1[3]) / 2.0)
                                p0_ctr = ((p0[0] + p0[2]) / 2.0, (p0[1] + p0[3]) / 2.0)
                                p1_ctr = ((p1[0] + p1[2]) / 2.0, (p1[1] + p1[3]) / 2.0)

                                curr_dist = float(np.sqrt((c0_ctr[0] - c1_ctr[0]) ** 2 + (c0_ctr[1] - c1_ctr[1]) ** 2))
                                prev_dist = float(np.sqrt((p0_ctr[0] - p1_ctr[0]) ** 2 + (p0_ctr[1] - p1_ctr[1]) ** 2))
                                dist_change = abs(curr_dist - prev_dist)

                                v0 = (c0_ctr[0] - p0_ctr[0], c0_ctr[1] - p0_ctr[1])
                                v1 = (c1_ctr[0] - p1_ctr[0], c1_ctr[1] - p1_ctr[1])
                                mag0 = float(np.sqrt(v0[0] ** 2 + v0[1] ** 2))
                                mag1 = float(np.sqrt(v1[0] ** 2 + v1[1] ** 2))
                                rel_speed = float(np.sqrt((v0[0] - v1[0]) ** 2 + (v0[1] - v1[1]) ** 2))

                                dot = v0[0] * v1[0] + v0[1] * v1[1]
                                cos_sim = dot / (mag0 * mag1) if (mag0 > 2.0 and mag1 > 2.0) else 0.0

                                # Peaceful companions: walking/moving in parallel lockstep with steady distance
                                is_parallel_peaceful = (cos_sim > 0.5 and dist_change < 18.0 and rel_speed < 22.0)

                                # Physical struggle: close contact with opposing/divergent velocity or rapid distance collapse
                                is_active_struggle = (
                                    curr_dist < 80
                                    and not is_parallel_peaceful
                                    and (cos_sim < 0.4)
                                    and (rel_speed > 30.0 or dist_change > 24.0 or ((mag0 + mag1) > 40.0 and cos_sim < 0.0))
                                )
                                if is_active_struggle:
                                    frame_has_struggle = True
                                    break
                            if frame_has_struggle:
                                break
                        if frame_has_struggle:
                            close_struggle_frames += 1

            if close_struggle_frames >= 2:
                has_violent_motion = True
                all_incidents.append({
                    "type": "violence_detected",
                    "severity": "High",
                    "severityScore": 86,
                    "confidence": 0.85,
                    "description": "High-velocity physical struggle / altercation detected between subjects.",
                    "camera_id": "cam_main",
                    "timestamp": time.time(),
                })

        # Multi-Modal Gating:
        # A deep learning sequence model (e.g. trained on UCF-Crime) often flags high anomaly scores
        # due to camera noise, indoor lighting, or scene background memorization (such as convenience store
        # aisles, merchandise shelving, and fluorescent reflections).
        # Interpersonal violence and physical altercations require verified kinematic indicators
        # (rapid strikes, falls, physical struggle, aggressive contact) or confirmed security incidents.
        # Solitary or multiple peaceful subjects (pedestrians, shoppers, coworkers) exhibiting nominal
        # kinematics without physical struggle/altercation do not constitute violence.
        if keras_result and keras_result["isThreat"]:
            if not has_violent_motion:
                reason = "Normal Pedestrian Activity" if max_people <= 1 else "Normal Activity / Peaceful Pedestrians"
                logger.info(f"[AI Gate] Suppressing false violence alarm: {reason} with nominal kinematics.")
                keras_result["isThreat"] = False
                keras_result["label"] = "NORMAL / SECURE"
                keras_result["threatType"] = reason
                # Multi-modal verification confidence that this sequence is nominal and secure
                keras_result["confidence"] = 0.95

        # Merge incidents
        seen_types = set()
        unique_incidents = []
        for inc in all_incidents:
            if inc["type"] not in seen_types:
                seen_types.add(inc["type"])
                unique_incidents.append(inc)

        # If Keras model classified verified violence, ensure it is in the incidents list
        if keras_result and keras_result["isThreat"]:
            if not any(i["type"] == "violence_detected" for i in unique_incidents):
                unique_incidents.append({
                    "type": "violence_detected",
                    "severity": "Critical" if keras_result["rawScore"] > 0.75 else "High",
                    "severityScore": int(keras_result["rawScore"] * 100),
                    "confidence": keras_result["confidence"],
                    "description": "Deep learning LSTM model detected physical violence / aggressive altercation pattern in video sequence.",
                    "camera_id": "cam_main",
                    "timestamp": time.time(),
                })

        # Calculate max severity score
        max_severity_score = 0
        overall_severity = "Low"
        for inc in unique_incidents:
            score = inc.get("severityScore", 0)
            if score > max_severity_score:
                max_severity_score = score
                overall_severity = inc.get("severity", "Medium")

        proc_ms = round((time.time() - t_start) * 1000)

        # Base verdict: Only flag threat if verified high/medium incidents meet the confidence threshold
        # or confirmed Keras multi-modal violence
        confirmed_incidents = [
            inc for inc in unique_incidents
            if inc.get("confidence", 0.0) >= threshold and inc.get("severity", "Low") in ("Critical", "High", "Medium")
        ]
        overall_threat = len(confirmed_incidents) > 0 or (keras_result is not None and keras_result["isThreat"])

        threat_label = "THREAT DETECTED" if overall_threat else "NORMAL / SECURE"
        threat_type = (
            confirmed_incidents[0]["description"] if confirmed_incidents else (
                keras_result.get("threatType", "Nominal Surveillance Feed") if keras_result else "Nominal Surveillance Feed"
            )
        )

        return {
            "status": "success",
            "isThreat": bool(overall_threat),
            "label": threat_label,
            "threatType": threat_type,
            "severity": overall_severity if overall_threat else "Low",
            "maxSeverityScore": max_severity_score if overall_threat else 0,
            "incidents": confirmed_incidents if overall_threat else [],
            "incidentsCount": len(confirmed_incidents) if overall_threat else 0,
            "kerasResult": keras_result,
            "objects": last_analysis.get("objects", []) if last_analysis else [],
            "poses": last_analysis.get("poses", []) if last_analysis else [],
            "annotatedFrame": last_analysis.get("annotatedFrame") if last_analysis else None,
            "framesProcessed": n,
            "processingTimeMs": proc_ms
        }

    def render_overlay(
        self,
        frame: np.ndarray,
        detections: List[Dict[str, Any]],
        poses: List[Dict[str, Any]],
        incidents: List[Dict[str, Any]]
    ) -> np.ndarray:
        """
        Draw visual annotations:
        - Bounding boxes for persons and valuable objects
        - Pose skeleton lines and joints
        - Incident alert banners / warning boxes
        """
        output = frame.copy()
        h, w = output.shape[:2]

        # 1. Draw Poses (skeleton joints)
        if self.pose_estimator and poses:
            output = self.pose_estimator.draw_pose(output, poses)

        # 2. Draw Object Detections
        for det in detections:
            bbox = [int(v) for v in det["bbox"]]
            conf = det.get("conf", 0.0)
            c_name = det.get("class_name", "object")

            is_valuable = c_name in {"backpack", "handbag", "suitcase", "laptop", "cell phone"}
            color = (255, 180, 0) if is_valuable else ((0, 240, 120) if c_name == "person" else (200, 200, 200))

            cv2.rectangle(output, (bbox[0], bbox[1]), (bbox[2], bbox[3]), color, 2)
            label = f"{c_name.upper()} {int(conf*100)}%"
            # Label background
            (lw, lh), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.45, 1)
            cv2.rectangle(output, (bbox[0], max(0, bbox[1] - lh - 6)), (bbox[0] + lw + 6, max(0, bbox[1])), color, -1)
            cv2.putText(output, label, (bbox[0] + 3, max(lh + 2, bbox[1] - 4)), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 0), 1, cv2.LINE_AA)

        # 3. Draw Incident Bounding Boxes and Banners
        for inc in incidents:
            inc_bbox = inc.get("bbox")
            if inc_bbox and len(inc_bbox) == 4:
                ib = [int(v) for v in inc_bbox]
                # High-contrast red/critical border
                cv2.rectangle(output, (ib[0], ib[1]), (ib[2], ib[3]), (0, 0, 255), 3)
                alert_text = f"ALERT: {inc.get('type', 'threat').replace('_', ' ').upper()}"
                cv2.putText(output, alert_text, (ib[0], max(20, ib[1] - 8)), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 0, 255), 2, cv2.LINE_AA)

        # 4. Top status banner
        if incidents:
            top_text = f"CRITICAL INCIDENTS: {len(incidents)} DETECTED"
            cv2.rectangle(output, (0, 0), (w, 32), (0, 0, 180), -1)
            cv2.putText(output, top_text, (12, 22), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2, cv2.LINE_AA)

        return output

    def _frame_to_base64(self, frame: np.ndarray) -> str:
        # If RGB, convert to BGR for cv2 imencode
        if len(frame.shape) == 3:
            bgr = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        else:
            bgr = frame
        _, buffer = cv2.imencode(".jpg", bgr, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
        b64 = base64.b64encode(buffer).decode("utf-8")
        return f"data:image/jpeg;base64,{b64}"

