from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.config import settings
from backend.core.database import get_conn, get_cursor, get_db_stats
from backend.dependencies import require_auth
from backend.integrations.xcockpit_client import xcockpit_client

router = APIRouter()


@router.get("/status")
async def system_status(_=Depends(require_auth)) -> dict:
    stats = get_db_stats()
    xcockpit_ok = await xcockpit_client.health_check()
    return {
        "status": "ok",
        "version": "1.0.0",
        "database": stats,
        "xcockpit": {
            "connected": xcockpit_ok,
            "base_url": settings.xcockpit.base_url or "(not configured)",
            "customer_key": settings.xcockpit.customer_key[:8] + "..." if settings.xcockpit.customer_key else "(not set)",
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
