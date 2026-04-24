from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

XCOCKPIT_FIELD_MAP: dict[str, str] = {
    "alertId":      "xcockpit_event_id",
    "ruleId":       "xcockpit_rule_id",
    "ruleName":     "xcockpit_rule_name",
    "riskLevel":    "severity",
    "sourceIp":     "src_ip",
    "destIp":       "dst_ip",
    "sourcePort":   "src_port",
    "destPort":     "dst_port",
    "protocol":     "protocol",
    "hostname":     "host",
    "username":     "username",
    "processName":  "process_name",
    "filePath":     "file_path",
    "category":     "category",
    "eventType":    "event_type",
    "description":  "message",
    "detectedAt":   "_time",
    "tags":         "tags",
}

SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "info",
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    # Numeric risk levels XCockpit sometimes uses
    "5":        "critical",
    "4":        "high",
    "3":        "medium",
    "2":        "low",
    "1":        "info",
}


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    if isinstance(value, (int, float)):
        # Unix timestamp
        return datetime.utcfromtimestamp(value)
    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo:
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            except ValueError:
                continue
    raise ValueError(f"Cannot parse timestamp: {value!r}")


def normalize(raw: dict[str, Any], source: str = "xcockpit", sourcetype: str = "xcockpit:event") -> dict[str, Any]:
    """Map a raw XCockpit event dict to the internal schema dict."""
    event: dict[str, Any] = {
        "source": source,
        "sourcetype": sourcetype,
        "raw": raw,
        "_indextime": datetime.utcnow(),
    }

    for xcockpit_key, internal_key in XCOCKPIT_FIELD_MAP.items():
        value = raw.get(xcockpit_key)
        if value is None:
            continue

        if internal_key == "_time":
            try:
                event["_time"] = _parse_timestamp(value)
            except ValueError as e:
                logger.warning("Timestamp parse failed: %s", e)
        elif internal_key == "severity":
            event["severity"] = SEVERITY_MAP.get(str(value), str(value).lower())
        elif internal_key in ("src_port", "dst_port"):
            try:
                event[internal_key] = int(value)
            except (TypeError, ValueError):
                pass
        else:
            event[internal_key] = value

    # Fallback: use _indextime as _time if missing
    if "_time" not in event:
        event["_time"] = event["_indextime"]

    # Build dedup hash
    dedup_key = event.get("xcockpit_event_id") or json.dumps(raw, sort_keys=True)
    event["_hash"] = hashlib.sha256(dedup_key.encode()).hexdigest()

    return event


def normalize_batch(
    raws: list[dict[str, Any]],
    source: str = "xcockpit",
    sourcetype: str = "xcockpit:event",
) -> tuple[list[dict[str, Any]], list[str]]:
    """Normalize a batch of raw events. Returns (good, error_messages)."""
    good: list[dict[str, Any]] = []
    errors: list[str] = []
    for raw in raws:
        try:
            good.append(normalize(raw, source, sourcetype))
        except Exception as e:
            errors.append(str(e))
    return good, errors
