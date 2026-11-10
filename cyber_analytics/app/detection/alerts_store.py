"""Thread-safe in-memory alert store for live cybersecurity alerts.

Serves as the runtime buffer until Phase 5 introduces persistent cyber_alerts table storage.
"""

from __future__ import annotations

from collections import deque
from threading import Lock
from typing import Sequence

from app.detection.rules import Alert, Severity


class AlertStore:
    """Thread-safe ring buffer for generated alerts."""

    def __init__(self, maxlen: int = 2000):
        self._maxlen = maxlen
        self._alerts: deque[Alert] = deque(maxlen=maxlen)
        self._lock = Lock()

    def add(self, alert: Alert) -> None:
        with self._lock:
            self._alerts.appendleft(alert)

    def add_many(self, alerts: Sequence[Alert]) -> None:
        with self._lock:
            for alert in alerts:
                self._alerts.appendleft(alert)

    def list_alerts(
        self,
        *,
        limit: int = 100,
        severity: str | Severity | None = None,
        entity_id: str | None = None,
        rule_id: str | None = None,
    ) -> list[Alert]:
        with self._lock:
            results: list[Alert] = []
            sev_filter = severity.value if isinstance(severity, Severity) else severity
            for alert in self._alerts:
                if sev_filter and alert.severity != sev_filter:
                    continue
                if entity_id and alert.entity_id != entity_id and alert.user != entity_id and alert.ip != entity_id and alert.camera != entity_id:
                    continue
                if rule_id and alert.rule_id != rule_id:
                    continue
                results.append(alert)
                if len(results) >= limit:
                    break
            return results

    def clear(self) -> None:
        with self._lock:
            self._alerts.clear()

    def count(self) -> int:
        with self._lock:
            return len(self._alerts)


alert_store = AlertStore()
