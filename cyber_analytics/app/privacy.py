"""Hashing helpers so raw IPs/tokens never sit in the event log."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Mapping

_REDACT_KEYS = frozenset(
    {
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "apikey",
        "secret",
        "id_token",
    }
)


def hmac_hex(value: str, secret: str) -> str:
    """Stable HMAC-SHA256 hex digest of ``value``."""
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_ip(ip: str) -> str:
    """Return a coarse display form (last IPv4 octet dropped). IPv6 is truncated."""
    if not ip:
        return "unknown"
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3] + ["xxxx"])
    octets = ip.split(".")
    if len(octets) == 4:
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return "unknown"


def device_fingerprint(user_agent: str, ip: str) -> str:
    """SHA-256 of user-agent + IP as specified for device correlation."""
    raw = f"{user_agent or ''}|{ip or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sanitize_metadata(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Drop credential-like keys recursively. Never persist passwords or tokens."""
    if not payload:
        return {}
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower() in _REDACT_KEYS:
            continue
        if isinstance(value, dict):
            cleaned[key] = sanitize_metadata(value)
        elif isinstance(value, str) and re.search(r"bearer\s+\S+", value, re.I):
            cleaned[key] = "[redacted]"
        else:
            cleaned[key] = value
    return cleaned
