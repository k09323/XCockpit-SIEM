from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from backend.core import database as db
from backend.integrations.normalizer import normalize_batch

logger = logging.getLogger(__name__)

# WebSocket clients that want live-tail events
_ws_subscribers: set[asyncio.Queue] = set()


def subscribe_live() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _ws_subscribers.add(q)
    return q


def unsubscribe_live(q: asyncio.Queue) -> None:
    _ws_subscribers.discard(q)


async def _fan_out(events: list[dict]) -> None:
    dead = set()
    for q in _ws_subscribers:
        for ev in events:
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                dead.add(q)
    for q in dead:
        _ws_subscribers.discard(q)


def _insert_batch(normalized: list[dict[str, Any]]) -> tuple[int, int]:
    """Bulk-insert normalized events into DuckDB. Returns (inserted, dupes)."""
    if not normalized:
        return 0, 0

    conn = db.get_conn()
    inserted = 0
    dupes = 0

    # Collect existing hashes to skip dupes efficiently
    hashes = [e["_hash"] for e in normalized]
    placeholders = ", ".join(["?"] * len(hashes))
    existing_hashes = set(
        row[0]
        for row in conn.execute(
            f"SELECT _hash FROM events WHERE _hash IN ({placeholders})", hashes
        ).fetchall()
    )

    to_insert = [e for e in normalized if e["_hash"] not in existing_hashes]
    dupes = len(normalized) - len(to_insert)

    if not to_insert:
        return 0, dupes

    rows = []
    for e in to_insert:
        rows.append((
            e.get("source", "xcockpit"),
            e.get("sourcetype", "xcockpit:event"),
            e["_time"],
            e["_indextime"],
            e.get("host"),
            e.get("severity"),
            e.get("category"),
            e.get("event_type"),
            e.get("src_ip"),
            e.get("dst_ip"),
            e.get("src_port"),
            e.get("dst_port"),
            e.get("protocol"),
            e.get("username"),
            e.get("process_name"),
            e.get("file_path"),
            json.dumps(e.get("raw", {})),
            e.get("message"),
            e.get("tags"),
            e.get("xcockpit_event_id"),
            e.get("xcockpit_rule_id"),
            e.get("xcockpit_rule_name"),
            e["_hash"],
        ))

    conn.executemany(
        """INSERT OR IGNORE INTO events
           (source, sourcetype, _time, _indextime, host, severity, category,
            event_type, src_ip, dst_ip, src_port, dst_port, protocol, username,
            process_name, file_path, raw, message, tags, xcockpit_event_id,
            xcockpit_rule_id, xcockpit_rule_name, _hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    inserted = len(to_insert)
    return inserted, dupes


async def process_batch(
    raw_events: list[dict[str, Any]],
    source: str = "xcockpit",
    sourcetype: str = "xcockpit:event",
    batch_id: str | None = None,
) -> dict[str, Any]:
    """Full pipeline: normalize → dedup → store → fan-out."""
    t0 = time.monotonic()

    normalized, errors = normalize_batch(raw_events, source, sourcetype)
    inserted, dupes = _insert_batch(normalized)

    duration_ms = int((time.monotonic() - t0) * 1000)

    # Log ingest stats
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO ingest_log (source, batch_id, events_count, errors_count, duration_ms) VALUES (?, ?, ?, ?, ?)",
        [source, batch_id, inserted, len(errors), duration_ms],
    )

    if _ws_subscribers and normalized:
        await _fan_out(normalized[:50])  # cap live-tail at 50 per batch

    logger.info(
        "Batch processed: %d raw → %d inserted, %d dupes, %d errors in %dms",
        len(raw_events), inserted, dupes, len(errors), duration_ms,
    )

    return {
        "accepted": inserted,
        "rejected": len(errors),
        "dupes": dupes,
        "errors": errors,
        "duration_ms": duration_ms,
        "batch_id": batch_id,
    }
