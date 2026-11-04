"""Machine learning anomaly detection using scikit-learn IsolationForest.

Features:
- Behavioral scoring in [0.0, 1.0] (higher = more anomalous).
- Hybrid scoring: IsolationForest density estimation combined with per-user baseline deviation.
- Human-readable explainability with top contributing features.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from app.detection.rules import Alert, Severity
from app.ml.features import (
    FEATURE_NAMES,
    UserBaseline,
    build_user_baseline,
    extract_features_from_event,
)
from app.models import EventType, SecurityEvent


@dataclass
class AnomalyDetectionResult:
    """Detailed anomaly detection output."""

    is_anomaly: bool
    anomaly_score: float  # [0.0, 1.0]
    reasons: list[str]
    explanation: str
    features: dict[str, float]
    user_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 4),
            "reasons": self.reasons,
            "explanation": self.explanation,
            "features": self.features,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat(),
        }


class MLAnomalyDetector:
    """Per-user behavioral anomaly detector powered by scikit-learn IsolationForest."""

    def __init__(
        self,
        *,
        contamination: float = 0.05,
        n_estimators: int = 100,
        score_threshold: float = 0.65,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.score_threshold = score_threshold
        self.random_state = random_state

        self.model: IsolationForest = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )
        self.is_fitted: bool = False
        self.baselines: dict[str, UserBaseline] = {}

    def fit_from_events(self, events: Sequence[SecurityEvent]) -> MLAnomalyDetector:
        """Fit IsolationForest and compute per-user behavioral baselines."""
        if not events:
            return self

        # 1. Group events by user to compute baselines
        users = {e.user_id for e in events if e.user_id}
        for u in users:
            self.baselines[u] = build_user_baseline(u, events)

        # 2. Extract feature matrix
        X_rows: list[list[float]] = []
        for e in events:
            if not e.user_id:
                continue
            b = self.baselines.get(e.user_id)
            feats = extract_features_from_event(e, history=events, baseline=b)
            X_rows.append([feats[name] for name in FEATURE_NAMES])

        if len(X_rows) >= 5:
            X = np.array(X_rows, dtype=np.float64)
            self.model.fit(X)
            self.is_fitted = True

        return self

    def fit(self, X: np.ndarray, user_baselines: dict[str, UserBaseline] | None = None) -> MLAnomalyDetector:
        """Direct fit on a feature array."""
        if X.shape[0] >= 5:
            self.model.fit(X)
            self.is_fitted = True
        if user_baselines:
            self.baselines.update(user_baselines)
        return self

    def score_vector(self, feature_values: list[float] | np.ndarray) -> float:
        """Calculate normalized anomaly score in [0.0, 1.0] from IsolationForest."""
        arr = np.array(feature_values, dtype=np.float64).reshape(1, -1)
        if not self.is_fitted:
            # Fallback heuristic if model not yet fitted on sufficient history
            return 0.1

        # decision_function yields: positive for inliers, negative for outliers
        dec = float(self.model.decision_function(arr)[0])
        score = 1.0 / (1.0 + math.exp(dec * 18.0))
        return float(np.clip(score, 0.0, 1.0))

    def explain(
        self,
        features: dict[str, float],
        baseline: UserBaseline | None,
        event: SecurityEvent | None = None,
    ) -> list[str]:
        """Generate human-readable contributing reasons comparing features to user baseline."""
        reasons: list[str] = []

        login_hour = features.get("login_hour", 12.0)
        hour_int = int(login_hour)
        minute_int = int((login_hour - hour_int) * 60)
        time_str = f"{hour_int:02d}:{minute_int:02d}"

        day_of_week = int(features.get("day_of_week", 0))
        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        day_str = day_names[day_of_week] if 0 <= day_of_week < 7 else "Unknown"

        is_new_dev = (
            (baseline.is_device_new(event.device_fingerprint) if (baseline and event) else False)
            or (features.get("is_new_device", 0.0) >= 1.0)
        )
        is_new_ip = (
            (baseline.is_ip_new(event.ip_address) if (baseline and event) else False)
            or (features.get("is_new_ip", 0.0) >= 1.0)
        )

        if baseline:
            # Check 1: Unusual hour
            if baseline.is_hour_unusual(hour_int):
                active_h_str = f"{baseline.min_hour:02d}:00-{baseline.max_hour:02d}:00"
                reasons.append(f"Login at {time_str}, user normally active {active_h_str}")

            # Check 2: Unusual day
            if baseline.active_days and day_of_week not in baseline.active_days:
                reasons.append(f"Activity on {day_str} (outside usual active days)")

            # Check 3: Never-seen device
            if is_new_dev:
                reasons.append("Access from a never-seen device")

            # Check 4: Never-seen IP
            if is_new_ip:
                reasons.append("Access from a never-seen IP address")

            # Check 5: Request rate spike
            req_rate = features.get("request_rate", 1.0)
            if req_rate > max(baseline.avg_request_rate * 3.0, 20.0):
                reasons.append(
                    f"Request rate spike ({int(req_rate)} req/hr vs usual avg {baseline.avg_request_rate:.1f}/hr)"
                )

            # Check 6: Video access spike
            if is_new_dev and event and event.event_type in ("VIDEO_DOWNLOAD", EventType.VIDEO_DOWNLOAD.value):
                reasons.append("Video download requested from an untrusted device")
            vid_rate = features.get("videos_accessed_per_hour", 0.0)
            if vid_rate >= 10.0 and vid_rate > max(baseline.avg_video_rate * 3.0, 5.0):
                reasons.append(
                    f"Mass video access spike ({int(vid_rate)} videos/hr vs usual avg {baseline.avg_video_rate:.1f}/hr)"
                )
            elif vid_rate > max(baseline.avg_video_rate * 2.0, 5.0):
                reasons.append(
                    f"Video access spike ({int(vid_rate)} videos/hr vs usual avg {baseline.avg_video_rate:.1f}/hr)"
                )
        else:
            # Generic checks when no historical baseline exists
            if is_new_dev:
                reasons.append("Access from a never-seen device")
            if is_new_ip:
                reasons.append("Access from a never-seen IP address")
            if is_new_dev and event and event.event_type in ("VIDEO_DOWNLOAD", EventType.VIDEO_DOWNLOAD.value):
                reasons.append("Video download requested from an untrusted device")
            vid_rate = features.get("videos_accessed_per_hour", 0.0)
            if vid_rate > 16.0:
                reasons.append(f"Mass video access rate ({int(vid_rate)} videos/hr)")
            elif vid_rate > 8.0:
                reasons.append(f"High video access rate ({int(vid_rate)} videos/hr)")

        if not reasons:
            reasons.append("Statistical deviation from normal population pattern")

        return reasons

    def detect(
        self,
        event: SecurityEvent,
        history: Sequence[SecurityEvent] = (),
    ) -> AnomalyDetectionResult:
        """Run ML anomaly detection for a single event."""
        user_id = event.user_id or event.username_attempted or "unknown"
        baseline = self.baselines.get(user_id)

        feats = extract_features_from_event(event, history=history, baseline=baseline)
        feat_vector = [feats[name] for name in FEATURE_NAMES]

        ml_score = self.score_vector(feat_vector)
        reasons = self.explain(feats, baseline, event)

        is_new_dev = (
            (baseline.is_device_new(event.device_fingerprint) if baseline else False)
            or (feats.get("is_new_device", 0.0) >= 1.0)
        )
        is_new_ip = (
            (baseline.is_ip_new(event.ip_address) if baseline else False)
            or (feats.get("is_new_ip", 0.0) >= 1.0)
        )

        # Baseline behavioral score
        b_score = 0.0
        if baseline:
            hour_int = int(feats.get("login_hour", 12.0))
            day_int = int(feats.get("day_of_week", 0))

            if is_new_dev:
                b_score += 0.25
            if is_new_ip:
                b_score += 0.20
            if baseline.is_hour_unusual(hour_int):
                b_score += 0.35
            if baseline.active_days and day_int not in baseline.active_days:
                if is_new_dev or baseline.is_hour_unusual(hour_int):
                    b_score += 0.20
            if feats.get("request_rate", 1.0) > max(baseline.avg_request_rate * 3.0, 20.0):
                b_score += 0.25
            if is_new_dev and event.event_type in ("VIDEO_DOWNLOAD", EventType.VIDEO_DOWNLOAD.value):
                b_score += 0.25
            vid_rate = feats.get("videos_accessed_per_hour", 0.0)
            if vid_rate >= 10.0 and vid_rate > max(baseline.avg_video_rate * 3.0, 5.0):
                b_score += 0.65
            elif vid_rate > max(baseline.avg_video_rate * 2.0, 5.0):
                b_score += 0.35
        else:
            if is_new_dev:
                b_score += 0.25
            if is_new_ip:
                b_score += 0.20
            if is_new_dev and event.event_type in ("VIDEO_DOWNLOAD", EventType.VIDEO_DOWNLOAD.value):
                b_score += 0.25
            vid_rate = feats.get("videos_accessed_per_hour", 0.0)
            if vid_rate > 16.0:
                b_score += 0.65
            elif vid_rate > 8.0:
                b_score += 0.35

        b_score = min(b_score, 1.0)

        # Hybrid fusion: ML density + User baseline deviation
        if b_score > 0:
            final_score = max(ml_score * 0.4 + b_score * 0.6, b_score)
        else:
            final_score = ml_score

        final_score = float(np.clip(final_score, 0.0, 1.0))
        is_anomaly = final_score >= self.score_threshold

        explanation = ", ".join(reasons)

        return AnomalyDetectionResult(
            is_anomaly=is_anomaly,
            anomaly_score=final_score,
            reasons=reasons,
            explanation=explanation,
            features=feats,
            user_id=user_id,
            timestamp=event.timestamp,
        )

    def as_alert(
        self,
        event: SecurityEvent,
        history: Sequence[SecurityEvent] = (),
    ) -> Alert | None:
        """Return an Alert object if the event is detected as an ML anomaly."""
        res = self.detect(event, history=history)
        if not res.is_anomaly:
            return None

        # Severity determined by anomaly score
        if res.anomaly_score >= 0.85:
            sev = Severity.CRITICAL
        elif res.anomaly_score >= 0.70:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM

        return Alert(
            rule_id="ML_ANOMALY",
            severity=sev,
            entity_type="user",
            entity_id=res.user_id or event.ip_address,
            evidence={
                "anomaly_score": round(res.anomaly_score, 4),
                "features": res.features,
                "reasons": res.reasons,
                "ip_address": event.ip_address,
                "device_fingerprint": event.device_fingerprint,
            },
            reason=res.explanation,
            confidence=round(res.anomaly_score, 4),
            created_at=event.timestamp,
        )
