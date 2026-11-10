import numpy as np
from scipy.optimize import linear_sum_assignment
from typing import List, Dict, Any

class SimpleKalmanBoxTracker:
    """Lightweight pure NumPy Kalman filter for bounding boxes [x1, y1, x2, y2]."""
    def __init__(self, bbox: List[float], conf: float, cls: int, track_id: int):
        self.bbox = bbox
        self.conf = conf
        self.cls = cls
        self.track_id = track_id
        
        # State: [cx, cy, s, r, vx, vy, vs]
        # s = area = w*h, r = aspect ratio = w/h
        w = max(1.0, bbox[2] - bbox[0])
        h = max(1.0, bbox[3] - bbox[1])
        self.x = np.array([bbox[0] + w/2, bbox[1] + h/2, w*h, w/h, 0, 0, 0], dtype=float)
        
        self.P = np.diag([10, 10, 10, 10, 1000, 1000, 1000]).astype(float)
        self.F = np.eye(7)
        self.F[0, 4] = 1.0
        self.F[1, 5] = 1.0
        self.F[2, 6] = 1.0
        
        self.H = np.zeros((4, 7))
        self.H[0, 0] = 1.0
        self.H[1, 1] = 1.0
        self.H[2, 2] = 1.0
        self.H[3, 3] = 1.0
        
        self.R = np.diag([1, 1, 10, 10]).astype(float)
        self.Q = np.diag([1, 1, 1, 1, 0.01, 0.01, 0.0001]).astype(float)
        
        self.time_since_update = 0
        self.hit_streak = 1

    def predict(self) -> List[float]:
        self.x = np.dot(self.F, self.x)
        self.P = np.dot(np.dot(self.F, self.P), self.F.T) + self.Q
        self.time_since_update += 1
        return self._to_bbox()

    def update(self, bbox: List[float], conf: float = None):
        w = max(1.0, bbox[2] - bbox[0])
        h = max(1.0, bbox[3] - bbox[1])
        z = np.array([bbox[0] + w/2, bbox[1] + h/2, w*h, w/h], dtype=float)
        
        y = z - np.dot(self.H, self.x)
        S = np.dot(np.dot(self.H, self.P), self.H.T) + self.R
        K = np.dot(np.dot(self.P, self.H.T), np.linalg.inv(S))
        
        self.x = self.x + np.dot(K, y)
        self.P = self.P - np.dot(np.dot(K, self.H), self.P)
        
        self.bbox = bbox
        if conf is not None:
            self.conf = conf
        self.time_since_update = 0
        self.hit_streak += 1

    def _to_bbox(self) -> List[float]:
        cx, cy, s, r = self.x[0], self.x[1], self.x[2], self.x[3]
        w = np.sqrt(max(1.0, s * max(0.1, r)))
        h = s / max(1.0, w)
        return [float(cx - w/2), float(cy - h/2), float(cx + w/2), float(cy + h/2)]


class ByteTracker:
    """
    Multi-object tracker associating detections across frames using IoU and Kalman filtering.
    """
    def __init__(self, max_age: int = 15, min_hits: int = 2, iou_threshold: float = 0.3):
        self.max_age = max_age
        self.min_hits = min_hits
        self.iou_threshold = iou_threshold
        self.trackers: List[SimpleKalmanBoxTracker] = []
        self.frame_count = 0
        self.next_id = 1

    def update(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        self.frame_count += 1
        
        # Predict current trackers
        for trk in self.trackers:
            trk.predict()
            
        trk_boxes = [trk._to_bbox() for trk in self.trackers]
        det_boxes = [d['bbox'] for d in detections]
        
        matched_indices = []
        if trk_boxes and det_boxes:
            iou_matrix = np.zeros((len(trk_boxes), len(det_boxes)), dtype=float)
            for i, tb in enumerate(trk_boxes):
                for j, db in enumerate(det_boxes):
                    iou_matrix[i, j] = self._iou(tb, db)
            
            row_ind, col_ind = linear_sum_assignment(-iou_matrix)
            for r, c in zip(row_ind, col_ind):
                if iou_matrix[r, c] >= self.iou_threshold:
                    matched_indices.append((r, c))
        
        matched_trk = {r for r, _ in matched_indices}
        matched_det = {c for _, c in matched_indices}
        
        # Update matched
        for trk_idx, det_idx in matched_indices:
            self.trackers[trk_idx].update(detections[det_idx]['bbox'], detections[det_idx]['conf'])
            
        # Create new tracks
        for j in range(len(detections)):
            if j not in matched_det:
                new_trk = SimpleKalmanBoxTracker(
                    detections[j]['bbox'],
                    detections[j]['conf'],
                    detections[j].get('class', 0),
                    self.next_id
                )
                self.next_id += 1
                self.trackers.append(new_trk)
                
        # Remove dead tracks
        self.trackers = [t for t in self.trackers if t.time_since_update <= self.max_age]
        
        # Return active tracks
        output = []
        for trk in self.trackers:
            if trk.time_since_update == 0 and (trk.hit_streak >= self.min_hits or self.frame_count <= self.min_hits):
                output.append({
                    'bbox': trk.bbox,
                    'conf': trk.conf,
                    'class': trk.cls,
                    'track_id': trk.track_id
                })
        return output

    def _iou(self, boxA: List[float], boxB: List[float]) -> float:
        xA = max(boxA[0], boxB[0])
        yA = max(boxA[1], boxB[1])
        xB = min(boxA[2], boxB[2])
        yB = min(boxA[3], boxB[3])
        
        interArea = max(0.0, xB - xA) * max(0.0, yB - yA)
        boxAArea = max(1.0, (boxA[2] - boxA[0]) * (boxA[3] - boxA[1]))
        boxBArea = max(1.0, (boxB[2] - boxB[0]) * (boxB[3] - boxB[1]))
        
        return float(interArea / (boxAArea + boxBArea - interArea + 1e-6))

