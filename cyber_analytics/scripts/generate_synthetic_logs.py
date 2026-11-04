#!/usr/bin/env python3
"""Synthetic log generator and ML anomaly detection evaluator.

Generates realistic normal VMS activity + injected attacks and evaluates the
scikit-learn IsolationForest anomaly detection model, reporting precision,
recall, F1-score, and sample explanations.

Usage:
    python scripts/generate_synthetic_logs.py [--events 1000] [--attack-ratio 0.08] [--export-csv]
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

import numpy as np

# Add cyber_analytics root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.ml.anomaly import MLAnomalyDetector
from app.ml.features import FEATURE_NAMES, UserBaseline, extract_features_from_event
from app.models import EventType, SecurityEvent


class SyntheticEvent(NamedTuple):
    event: SecurityEvent
    is_attack: bool
    attack_type: str | None


def generate_synthetic_dataset(
    num_normal_days: int = 7,
    events_per_day: int = 150,
    attack_count: int = 35,
    seed: int = 42,
) -> list[SyntheticEvent]:
    """Generate realistic normal logs for personas plus injected attacks."""
    rng = random.Random(seed)
    base_time = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Personas
    personas = {
        "alice": {
            "user_id": "usr_alice",
            "name": "alice_soc",
            "hours": list(range(9, 18)),  # 09:00 - 18:00
            "days": [0, 1, 2, 3, 4],  # Mon - Fri
            "devices": ["fp_laptop_alice_corp", "fp_tablet_alice_soc"],
            "ips": ["10.0.1.15", "10.0.1.16"],
            "video_prob": 0.45,
        },
        "bob": {
            "user_id": "usr_bob",
            "name": "bob_operator",
            "hours": list(range(8, 17)),  # 08:00 - 17:00
            "days": [0, 1, 2, 3, 4],
            "devices": ["fp_desktop_bob_station1"],
            "ips": ["10.0.1.20"],
            "video_prob": 0.50,
        },
        "charlie_guard": {
            "user_id": "usr_charlie",
            "name": "charlie_security",
            "hours": [22, 23, 0, 1, 2, 3, 4, 5],  # Night shift
            "days": [0, 1, 2, 3, 4, 5, 6],
            "devices": ["fp_guard_console_main"],
            "ips": ["10.0.2.100"],
            "video_prob": 0.30,
        },
        "dave_admin": {
            "user_id": "usr_dave",
            "name": "dave_sysadmin",
            "hours": list(range(10, 19)),
            "days": [0, 1, 2, 3, 4],
            "devices": ["fp_admin_workstation_secure"],
            "ips": ["10.0.0.5"],
            "video_prob": 0.20,
        },
    }

    cameras = ["CAM-001-GATE", "CAM-002-LOBBY", "CAM-003-VAULT", "CAM-004-PERIMETER"]
    videos = [f"vid_{i:03d}" for i in range(1, 30)]

    all_synthetic: list[SyntheticEvent] = []

    # 1. Generate Normal Background Logs
    for day in range(num_normal_days):
        current_date = base_time + timedelta(days=day)
        weekday = current_date.weekday()

        for _ in range(events_per_day):
            # Pick a persona valid for this day
            active_personas = [p for p in personas.values() if weekday in p["days"]]
            if not active_personas:
                active_personas = [personas["charlie_guard"]]

            p = rng.choice(active_personas)
            hour = rng.choice(p["hours"])
            minute = rng.randint(0, 59)
            second = rng.randint(0, 59)
            event_ts = current_date.replace(hour=hour, minute=minute, second=second)

            # Determine normal event type
            if rng.random() < p["video_prob"]:
                ev_type = rng.choice([EventType.VIDEO_VIEW.value, EventType.VIDEO_DOWNLOAD.value])
                vid = rng.choice(videos)
                cam = rng.choice(cameras)
            elif rng.random() < 0.15:
                ev_type = EventType.LOGIN_SUCCESS.value
                vid = None
                cam = None
            elif rng.random() < 0.08:
                ev_type = EventType.CAMERA_HEARTBEAT.value
                vid = None
                cam = rng.choice(cameras)
            else:
                ev_type = EventType.VIDEO_VIEW.value
                vid = rng.choice(videos)
                cam = rng.choice(cameras)

            ev = SecurityEvent(
                id=uuid.uuid4(),
                timestamp=event_ts,
                event_type=ev_type,
                user_id=p["user_id"],
                username_attempted=p["name"],
                ip_address=rng.choice(p["ips"]),
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) VMSClient/2.4",
                device_fingerprint=rng.choice(p["devices"]),
                camera_id=cam,
                video_id=vid,
                success=True,
                event_metadata={"session_id": str(uuid.uuid4())[:8]},
            )
            all_synthetic.append(SyntheticEvent(event=ev, is_attack=False, attack_type=None))

    # Sort normal events by timestamp
    all_synthetic.sort(key=lambda s: s.event.timestamp)

    # 2. Inject Attacks / Anomalies
    attack_types = [
        "OFF_HOURS_CREDENTIAL_COMPROMISE",
        "SCRAPING_MASS_VIDEO_EXPORT",
        "WEEKEND_UNAUTHORIZED_PROBE",
        "NEW_DEVICE_AND_IP_ANOMALY",
    ]

    for i in range(attack_count):
        atk = rng.choice(attack_types)
        # Choose target day in the second half of the time window
        target_day = rng.randint(num_normal_days // 2, num_normal_days - 1)
        day_date = base_time + timedelta(days=target_day)

        if atk == "OFF_HOURS_CREDENTIAL_COMPROMISE":
            # Alice login at 03:22 AM from a completely new foreign device + IP
            ts = day_date.replace(hour=3, minute=rng.randint(10, 45), second=rng.randint(0, 59))
            ev = SecurityEvent(
                id=uuid.uuid4(),
                timestamp=ts,
                event_type=EventType.LOGIN_SUCCESS.value,
                user_id="usr_alice",
                username_attempted="alice_soc",
                ip_address="198.51.100.77",  # external unseen IP
                user_agent="python-requests/2.31.0",
                device_fingerprint="fp_unknown_linux_kali_box",
                camera_id=None,
                video_id=None,
                success=True,
                event_metadata={"threat_tag": "off_hours_compromise"},
            )
            all_synthetic.append(SyntheticEvent(event=ev, is_attack=True, attack_type=atk))

        elif atk == "SCRAPING_MASS_VIDEO_EXPORT":
            # Bob suddenly downloading 20 videos in 10 minutes from a new IP
            ts_start = day_date.replace(hour=14, minute=rng.randint(10, 40), second=0)
            for j in range(12):
                ev = SecurityEvent(
                    id=uuid.uuid4(),
                    timestamp=ts_start + timedelta(seconds=j * 15),
                    event_type=EventType.VIDEO_DOWNLOAD.value,
                    user_id="usr_bob",
                    username_attempted="bob_operator",
                    ip_address="203.0.113.44",
                    user_agent="Curl/8.4.0 (Automation)",
                    device_fingerprint="fp_scraping_bot_id",
                    camera_id=rng.choice(cameras),
                    video_id=f"secret_vid_{j}",
                    success=True,
                    event_metadata={"threat_tag": "mass_export_spike"},
                )
                all_synthetic.append(SyntheticEvent(event=ev, is_attack=True, attack_type=atk))

        elif atk == "WEEKEND_UNAUTHORIZED_PROBE":
            # Dave active on Sunday at 02:30 AM
            sunday_offset = (6 - base_time.weekday()) % 7
            ts = (base_time + timedelta(days=sunday_offset)).replace(hour=2, minute=rng.randint(15, 50))
            ev = SecurityEvent(
                id=uuid.uuid4(),
                timestamp=ts,
                event_type=EventType.VIDEO_VIEW.value,
                user_id="usr_dave",
                username_attempted="dave_sysadmin",
                ip_address="192.0.2.88",
                user_agent="Mozilla/5.0 (X11; Ubuntu)",
                device_fingerprint="fp_rogue_laptop",
                camera_id="CAM-003-VAULT",
                video_id="vault_cam_archive",
                success=True,
                event_metadata={"threat_tag": "weekend_probe"},
            )
            all_synthetic.append(SyntheticEvent(event=ev, is_attack=True, attack_type=atk))

        elif atk == "NEW_DEVICE_AND_IP_ANOMALY":
            # Charlie guard credentials from external IP with sudden high rate
            ts = day_date.replace(hour=12, minute=rng.randint(10, 50))  # daytime for night guard
            ev = SecurityEvent(
                id=uuid.uuid4(),
                timestamp=ts,
                event_type=EventType.LOGIN_SUCCESS.value,
                user_id="usr_charlie",
                username_attempted="charlie_security",
                ip_address="185.220.101.5",
                user_agent="Go-http-client/1.1",
                device_fingerprint="fp_anonymous_vpn_node",
                camera_id=None,
                video_id=None,
                success=True,
                event_metadata={"threat_tag": "guard_off_shift_anomaly"},
            )
            all_synthetic.append(SyntheticEvent(event=ev, is_attack=True, attack_type=atk))

    all_synthetic.sort(key=lambda s: s.event.timestamp)
    return all_synthetic


def evaluate_detector(
    dataset: list[SyntheticEvent],
    train_ratio: float = 0.65,
) -> dict[str, float]:
    """Train ML Anomaly Detector on normal baseline and evaluate on holdout set."""
    split_idx = int(len(dataset) * train_ratio)
    train_items = dataset[:split_idx]
    test_items = dataset[split_idx:]

    # Train only on normal historical events from the training split
    train_events = [item.event for item in train_items if not item.is_attack]

    detector = MLAnomalyDetector(contamination=0.04, n_estimators=100, score_threshold=0.65)
    detector.fit_from_events(train_events)

    tp = fp = tn = fn = 0
    sample_explanations: list[tuple[str, float, str]] = []

    history_for_features = list(train_events)

    for item in test_items:
        res = detector.detect(item.event, history=history_for_features)
        history_for_features.append(item.event)

        predicted_attack = res.is_anomaly
        actual_attack = item.is_attack

        if predicted_attack and actual_attack:
            tp += 1
            if len(sample_explanations) < 5:
                sample_explanations.append((item.attack_type or "ANOMALY", res.anomaly_score, res.explanation))
        elif predicted_attack and not actual_attack:
            fp += 1
        elif not predicted_attack and not actual_attack:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(test_items) if test_items else 0.0

    print("=" * 65)
    print("      CYBERSECURITY ANALYTICS ML ANOMALY DETECTION REPORT")
    print("=" * 65)
    print(f"Training events (normal):  {len(train_events)}")
    print(f"Test events evaluated:    {len(test_items)} (Attacks: {tp + fn}, Normal: {tn + fp})")
    print("-" * 65)
    print(f"Confusion Matrix:         TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"Precision:                {precision * 100:.2f}%")
    print(f"Recall:                   {recall * 100:.2f}%")
    print(f"F1-Score:                 {f1 * 100:.2f}%")
    print(f"Accuracy:                 {accuracy * 100:.2f}%")
    print("-" * 65)
    print("SAMPLE DETECTIONS WITH EXPLAINABILITY:")
    for atk_name, score, reason in sample_explanations:
        print(f" • [{atk_name}] Score: {score:.3f}")
        print(f"   Reason: {reason}")
    print("=" * 65)

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "tn": float(tn),
    }


def export_dataset_csv(dataset: list[SyntheticEvent], out_path: str = "synthetic_security_events.csv") -> None:
    """Export the generated synthetic dataset to a CSV file."""
    with open(out_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "event_type", "user_id", "username_attempted",
            "ip_address", "user_agent", "device_fingerprint",
            "camera_id", "video_id", "success", "is_attack", "attack_type"
        ])
        for item in dataset:
            e = item.event
            writer.writerow([
                e.timestamp.isoformat(), e.event_type, e.user_id, e.username_attempted,
                e.ip_address, e.user_agent, e.device_fingerprint,
                e.camera_id, e.video_id, e.success, item.is_attack, item.attack_type or ""
            ])
    print(f"[+] Exported {len(dataset)} synthetic security events to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Synthetic Log Generator & ML Anomaly Evaluator")
    parser.add_argument("--days", type=int, default=7, help="Days of normal background activity")
    parser.add_argument("--events-per-day", type=int, default=120, help="Average events per day")
    parser.add_argument("--attacks", type=int, default=30, help="Number of attacks to inject")
    parser.add_argument("--export-csv", action="store_true", help="Save synthetic dataset as CSV")
    parser.add_argument("--csv-path", default="synthetic_security_events.csv", help="Path for CSV export")
    args = parser.parse_args()

    print("[*] Generating synthetic security telemetry...")
    dataset = generate_synthetic_dataset(
        num_normal_days=args.days,
        events_per_day=args.events_per_day,
        attack_count=args.attacks,
    )
    print(f"[+] Total generated events: {len(dataset)}")

    if args.export_csv:
        export_dataset_csv(dataset, args.csv_path)

    print("[*] Training IsolationForest and evaluating anomaly detection performance...")
    metrics = evaluate_detector(dataset)

    if metrics["f1"] < 0.70:
        print("[!] Warning: F1 score is below 70%")
        sys.exit(1)
    else:
        print("[+] ML Anomaly Detection evaluation completed successfully!")


if __name__ == "__main__":
    main()
