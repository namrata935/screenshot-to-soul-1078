"""Feature extraction and per-user behavioral baseline for ML anomaly detection.

Features extracted per user event:
1. login_hour: float [0, 24)
2. day_of_week: int [0, 6] (0 = Monday, 6 = Sunday)
3. is_new_device: int (1 if device_fingerprint never seen for user, else 0)
4. is_new_ip: int (1 if ip_address never seen for user, else 0)
5. request_rate: float (events in the preceding 60 minutes)
6. videos_accessed_per_hour: float (VIDEO_VIEW/DOWNLOAD in preceding 60 minutes)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from app.models import EventType, SecurityEvent

FEATURE_NAMES = [
    "login_hour",
    "day_of_week",
    "is_new_device",
    "is_new_ip",
    "request_rate",
    "videos_accessed_per_hour",
]


def _norm_ts(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@dataclass
class UserBaseline:
    """Historical statistical profile for a single user."""

    user_id: str
    known_devices: set[str] = field(default_factory=set)
    known_ips: set[str] = field(default_factory=set)
    active_hours: set[int] = field(default_factory=set)  # set of hours observed (0-23)
    active_days: set[int] = field(default_factory=set)  # set of weekdays observed (0-6)
    min_hour: int = 9
    max_hour: int = 18
    total_events: int = 0
    total_video_access: int = 0
    avg_request_rate: float = 1.0
    avg_video_rate: float = 0.5
    max_observed_video_rate: float = 2.0

    def is_hour_unusual(self, hour: int) -> bool:
        if not self.active_hours:
            return False
        return hour not in self.active_hours

    def is_device_new(self, device_fp: str | None) -> bool:
        if not device_fp:
            return False
        return len(self.known_devices) > 0 and device_fp not in self.known_devices

    def is_ip_new(self, ip_address: str | None) -> bool:
        if not ip_address:
            return False
        return len(self.known_ips) > 0 and ip_address not in self.known_ips


def extract_features_from_event(
    event: SecurityEvent,
    history: Sequence[SecurityEvent] = (),
    baseline: UserBaseline | None = None,
    window_minutes: int = 60,
) -> dict[str, float]:
    """Extract the 6 core behavioral features for a single event."""
    ts = _norm_ts(event.timestamp)
    hour = float(ts.hour + ts.minute / 60.0)
    day = float(ts.weekday())

    cutoff = ts - timedelta(minutes=window_minutes)

    # Filter user's prior events strictly before or up to this event
    user_prior = [
        e for e in history
        if (e.user_id == event.user_id or e.username_attempted == event.username_attempted)
        and _norm_ts(e.timestamp) < ts
    ]

    # Prior known devices and IPs
    prior_devices = {e.device_fingerprint for e in user_prior if e.device_fingerprint}
    if baseline:
        prior_devices |= baseline.known_devices

    prior_ips = {e.ip_address for e in user_prior if e.ip_address}
    if baseline:
        prior_ips |= baseline.known_ips

    is_new_device = 1.0 if (prior_devices and event.device_fingerprint and event.device_fingerprint not in prior_devices) else 0.0
    is_new_ip = 1.0 if (prior_ips and event.ip_address and event.ip_address not in prior_ips) else 0.0

    # Recent events within the window (e.g. past 60 min)
    recent_events = [e for e in user_prior if _norm_ts(e.timestamp) >= cutoff]
    request_rate = float(len(recent_events) + 1)  # include current event

    video_types = {
        EventType.VIDEO_VIEW.value,
        EventType.VIDEO_DOWNLOAD.value,
        "VIDEO_VIEW",
        "VIDEO_DOWNLOAD",
    }
    recent_videos = [e for e in recent_events if e.event_type in video_types and e.success]
    current_is_video = 1 if (event.event_type in video_types and event.success) else 0
    videos_accessed_per_hour = float(len(recent_videos) + current_is_video)

    return {
        "login_hour": round(hour, 2),
        "day_of_week": day,
        "is_new_device": is_new_device,
        "is_new_ip": is_new_ip,
        "request_rate": request_rate,
        "videos_accessed_per_hour": videos_accessed_per_hour,
    }


def build_user_baseline(user_id: str, events: Sequence[SecurityEvent]) -> UserBaseline:
    """Compute historical behavioral profile from user's event history."""
    user_events = [
        e for e in events
        if (e.user_id == user_id or e.username_attempted == user_id)
    ]
    if not user_events:
        return UserBaseline(user_id=user_id)

    known_devices = {e.device_fingerprint for e in user_events if e.device_fingerprint}
    known_ips = {e.ip_address for e in user_events if e.ip_address}

    hours: set[int] = set()
    days: set[int] = set()
    total_videos = 0

    video_types = {
        EventType.VIDEO_VIEW.value,
        EventType.VIDEO_DOWNLOAD.value,
        "VIDEO_VIEW",
        "VIDEO_DOWNLOAD",
    }

    # Group into 1-hour buckets for rate calculations
    hour_buckets: dict[str, int] = {}
    video_buckets: dict[str, int] = {}

    for e in user_events:
        ts = _norm_ts(e.timestamp)
        hours.add(ts.hour)
        days.add(ts.weekday())
        bucket_key = ts.strftime("%Y-%m-%d-%H")
        hour_buckets[bucket_key] = hour_buckets.get(bucket_key, 0) + 1
        if e.event_type in video_types and e.success:
            total_videos += 1
            video_buckets[bucket_key] = video_buckets.get(bucket_key, 0) + 1

    min_h = min(hours) if hours else 9
    max_h = max(hours) if hours else 18

    num_buckets = max(len(hour_buckets), 1)
    avg_req_rate = sum(hour_buckets.values()) / float(num_buckets)
    avg_vid_rate = sum(video_buckets.values()) / float(num_buckets)
    max_vid_rate = max(video_buckets.values()) if video_buckets else 0.0

    return UserBaseline(
        user_id=user_id,
        known_devices=known_devices,
        known_ips=known_ips,
        active_hours=hours,
        active_days=days,
        min_hour=min_h,
        max_hour=max_h,
        total_events=len(user_events),
        total_video_access=total_videos,
        avg_request_rate=round(avg_req_rate, 2),
        avg_video_rate=round(avg_vid_rate, 2),
        max_observed_video_rate=float(max_vid_rate),
    )
