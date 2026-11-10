import cv2
import numpy as np
import logging
from typing import Tuple, Dict

logger = logging.getLogger(__name__)

class FrameValidator:
    """Validates video frames and detects corrupt or black frames."""

    def __init__(self):
        self.total_frames_checked = 0
        self.corrupted_frame_count = 0

    def validate_frame(self, frame: np.ndarray, frame_number: int = 0) -> Tuple[bool, str, Dict]:
        self.total_frames_checked += 1

        if frame is None:
            self.corrupted_frame_count += 1
            return False, "Frame is None", {}

        if not isinstance(frame, np.ndarray):
            self.corrupted_frame_count += 1
            return False, "Frame is not a numpy array", {}

        if len(frame.shape) < 2:
            self.corrupted_frame_count += 1
            return False, "Invalid dimensions", {}

        height, width = frame.shape[:2]
        if height < 16 or width < 16:
            self.corrupted_frame_count += 1
            return False, f"Frame too small: {width}x{height}", {}

        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if len(frame.shape) == 3 else frame
            mean_val = float(gray.mean())
            if mean_val < 0.5:
                self.corrupted_frame_count += 1
                return False, f"Frame is completely dark (mean={mean_val:.1f})", {"mean": mean_val}

            return True, "Valid", {
                "width": width,
                "height": height,
                "mean_brightness": mean_val,
                "std_dev": float(gray.std())
            }
        except Exception as e:
            return False, str(e), {}

