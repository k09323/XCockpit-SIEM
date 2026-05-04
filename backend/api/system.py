from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.config import settings
from backend.core.database import (
    clear_xcockpit_data,
    get_conn,
    get_customer_name,
    get_cursor,
    get_db_stats,
    get_xcockpit_config,
    reset_pull_cursors,
    set_xcockpit_config,
)
from backend.dependencies import require_auth
from backend.integrations.xcockpit_client import XCockpitClient, xcockpit_client

router = APIRouter()


def _require_admin(payload: dict = Depends(require_auth)) -> dict:
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return payload


def _mask(secret: str) -> str:
    """Show only the last 4 chars; rest as bullets. Empty → empty string."""
    if not secret:
        return ""
    if len(secret) <= 4:
        return "•" * len(secret)
    return "•" * (len(secret) - 4) + secret[-4:]


def _disk_usage() -> dict:
    """Return free-space stats for the filesystem hosting the DuckDB file.

    The file might not exist yet (fresh install) — fall back to its parent dir,
    then to '/'. Errors yield an empty payload so the UI can degrade gracefully.
    """
    candidates = [
        Path(settings.database.path),
        Path(settings.database.path).parent,
        Path("/"),
    ]
    for p in candidates:
        try:
            target = p if p.exists() else p.parent
            usage = shutil.disk_usage(str(target))
            free_pct = round(usage.free / usage.total * 100, 1) if usage.total else 0
            if free_pct >= 25:
                level = "ok"
            elif free_pct >= 10:
                level = "warn"
            else:
                level = "critical"
            return {
                "path": str(target),
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "free_percent": free_pct,
                "level": level,
            }
        except (OSError, FileNotFoundError):
            continue
    return {"path": None, "total_gb": 0, "used_gb": 0, "free_gb": 0,
            "free_percent": 0, "level": "unknown"}


@router.get("/status")
async def system_status(_=Depends(require_auth)) -> dict:
    stats = get_db_stats()
    xcockpit_ok = await xcockpit_client.health_check()
    cfg = get_xcockpit_config()
    customer_key = cfg["customer_key"]
    return {
        "status": "ok",
        "version": "1.0.0",
        "database": stats,
        "disk": _disk_usage(),
        "customer": {
            "name": get_customer_name(),               # from latest event; None until first pull
            "key": customer_key,                       # full key (admin can read it from xcockpit-config anyway)
            "key_short": (customer_key[:8] + "…") if customer_key else None,
        },
        "xcockpit": {
            "connected": xcockpit_ok,
            "base_url": cfg["base_url"] or "(not configured)",
            "customer_key": (customer_key[:8] + "...") if customer_key else "(not set)",
            "pull_interval_seconds": settings.xcockpit.pull_interval_seconds,
        },
    }


@router.get("/stats")
def system_stats(_=Depends(require_auth)) -> dict:
    conn = get_conn()
    rows = conn.execute(
        "SELECT data_type, SUM(fetched_count), SUM(new_count), AVG(duration_ms) "
        "FROM ingest_log WHERE ingested_at >= now() - INTERVAL '1 hour' "
        "GROUP BY data_type"
    ).fetchall()
    return {
        "last_1h": [
            {"type": r[0], "fetched": int(r[1] or 0), "new": int(r[2] or 0), "avg_ms": round(r[3] or 0, 1)}
            for r in rows
        ]
    }


@router.get("/xcockpit")
def xcockpit_pull_status(_=Depends(require_auth)) -> dict:
    cursors = {}
    for endpoint in ("alerts", "incidents", "activity_logs"):
        c = get_cursor(endpoint)
        cursors[endpoint] = {
            "last_timestamp": c["last_timestamp"].isoformat() if c["last_timestamp"] else None,
            "last_id": c["last_id"],
        }
    return {
        "pull_interval_seconds": settings.xcockpit.pull_interval_seconds,
        "cursors": cursors,
    }


@router.post("/pull/trigger")
async def trigger_pull(_=Depends(require_auth)) -> dict:
    from backend.core.scheduler import trigger_pull_now
    result = await trigger_pull_now()
    return result


@router.get("/mdr-statistic")
async def mdr_statistic(_=Depends(require_auth)) -> dict:
    data = await xcockpit_client.get_mdr_statistic()
    return data or {"error": "Failed to fetch MDR statistic from XCockpit"}


# ---------------------------------------------------------------------------
# XCockpit connection config (admin only)
# ---------------------------------------------------------------------------
#
# Admins can edit URL / customer_key / api_key from the Settings UI.
# The XCockpitClient reads these LIVE from DB on every request, so the next
# pull cycle picks up new values without restarting the service.

class XCockpitConfigRequest(BaseModel):
    base_url: str | None = None
    customer_key: str | None = None
    api_key: str | None = None  # send "" or omit to leave unchanged
    test_only: bool = False     # if True: don't persist, just verify
    # When customer_key changes, the LOCAL DB still contains the previous
    # customer's events. Setting this True drops all per-customer data tables
    # (edr_alerts, cyber_reports, incidents, activity_logs) so the new
    # customer starts fresh. Cursors are always reset on customer_key change.
    clear_data_on_customer_change: bool = True


@router.get("/xcockpit-config")
def read_xcockpit_config(_=Depends(_require_admin)) -> dict:
    cfg = get_xcockpit_config()
    return {
        "base_url": cfg["base_url"],
        "customer_key": cfg["customer_key"],
        # Never return raw api_key — return masked form for display only.
        "api_key_masked": _mask(cfg["api_key"]),
        "api_key_set": bool(cfg["api_key"]),
        "pull_interval_seconds": settings.xcockpit.pull_interval_seconds,
    }


@router.put("/xcockpit-config")
async def update_xcockpit_config(
    body: XCockpitConfigRequest, _=Depends(_require_admin)
) -> dict:
    # Empty string in api_key means "leave unchanged" (so the masked display
    # field can be sent back without overwriting the saved key).
    new_key = body.api_key if body.api_key else None

    if body.test_only:
        # Resolve effective values for testing without persisting:
        # use submitted values where provided, else current saved values.
        current = get_xcockpit_config()
        url = body.base_url or current["base_url"]
        ck = body.customer_key or current["customer_key"]
        ak = new_key or current["api_key"]
        ok, msg = await XCockpitClient.test_connection(url, ck, ak,
                                                        verify_ssl=settings.xcockpit.verify_ssl)
        return {"ok": ok, "message": msg}

    # Detect customer_key change BEFORE persisting — needed because once we
    # write the new value, get_xcockpit_config() returns the new value.
    previous = get_xcockpit_config()
    customer_changed = bool(
        body.customer_key
        and previous["customer_key"]
        and body.customer_key != previous["customer_key"]
    )

    # Persist
    set_xcockpit_config(
        base_url=body.base_url,
        customer_key=body.customer_key,
        api_key=new_key,
    )

    # Reset cursors / data when switching customer. Without this, the next
    # pull would call /_api/<NEW_customer>/alert?created=<OLD_customer's_cursor>
    # → events older than the stale cursor are silently dropped.
    cleared: dict[str, int] | None = None
    cursors_reset: int | None = None
    if customer_changed:
        if body.clear_data_on_customer_change:
            cleared = clear_xcockpit_data()  # also resets cursors
        else:
            cursors_reset = reset_pull_cursors()

    # Verify against the (now saved) values.
    cfg = get_xcockpit_config()
    ok, msg = await XCockpitClient.test_connection(
        cfg["base_url"], cfg["customer_key"], cfg["api_key"],
        verify_ssl=settings.xcockpit.verify_ssl,
    )

    # Trigger an immediate pull so the user sees data refresh without waiting
    # for the next scheduled cycle. Run in background — don't block the HTTP
    # response on it.
    if ok and customer_changed:
        import asyncio
        from backend.core.scheduler import trigger_pull_now
        asyncio.create_task(trigger_pull_now())

    return {
        "detail": "XCockpit config saved.",
        "verified": ok,
        "message": msg,
        "customer_changed": customer_changed,
        "cleared_rows": cleared,           # dict if data was cleared, else None
        "cursors_reset": cursors_reset,    # int if only cursors reset, else None
        "base_url": cfg["base_url"],
        "customer_key": cfg["customer_key"],
        "api_key_masked": _mask(cfg["api_key"]),
    }
