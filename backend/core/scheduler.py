from __future__ import annotations

"""APScheduler jobs for pulling data from XCockpit.

Pull flow:
1. GET /alert?created=<last_pull_time>  →  list of {id, type, created}
2. For each CYCRAFT_E: GET /edr_alert/<id>/json  →  upsert edr_alerts
3. For each CYCRAFT_C: GET /cyber_situation_report/<id>/json  →  upsert cyber_reports
4. GET /incident?created_after=<last_pull_time>  →  upsert incidents
5. GET /act-log?source=xcockpit&stime=<last_pull_time>  →  insert activity_logs
"""

import logging
import time
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from backend.config import settings

logger = logging.getLogger(__name__)
_scheduler: AsyncIOScheduler | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _cursor_or_default(endpoint: str, default_hours_back: int = 24) -> str:
    from backend.core.database import get_cursor
    cursor = get_cursor(endpoint)
    if cursor["last_timestamp"]:
        # Add 1 second to avoid re-fetching the exact last record
        ts: datetime = cursor["last_timestamp"]
        if isinstance(ts, str):
            from dateutil.parser import parse
            ts = parse(ts)
        ts = ts + timedelta(seconds=1)
        return ts.strftime("%Y-%m-%dT%H:%M:%S")
    # Default: look back N hours
    dt = datetime.now(timezone.utc) - timedelta(hours=default_hours_back)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


async def _pull_alerts() -> None:
    """Pull Alert List → fetch EDR alerts + Cyber reports."""
    from backend.core.database import (
        get_cursor, update_cursor, upsert_edr_alert,
        upsert_cyber_report, log_ingest,
    )
    from backend.integrations.xcockpit_client import xcockpit_client

    t0 = time.monotonic()
    since = _cursor_or_default("alerts", default_hours_back=24)
    logger.info("Pulling alerts since %s", since)

    alert_list = await xcockpit_client.get_alert_list(since)
    if not alert_list:
        return

    edr_new = edr_err = cyber_new = cyber_err = 0
    latest_ts: str | None = None

    for item in alert_list:
        item_created = item.get("created", "")
        item_id = item.get("id", "")
        item_type = item.get("type", "")

        if not latest_ts or item_created > latest_ts:
            latest_ts = item_created

        if item_type == "CYCRAFT_E":
            data = await xcockpit_client.get_edr_alert(item_id)
            if data:
                try:
                    is_new = upsert_edr_alert(data)
                    if is_new:
                        edr_new += 1
                except Exception as e:
                    logger.error("EDR alert upsert failed %s: %s", item_id, e)
                    edr_err += 1
            else:
                edr_err += 1

        elif item_type == "CYCRAFT_C":
            data = await xcockpit_client.get_cyber_situation_report(item_id)
            if data:
                try:
                    is_new = upsert_cyber_report(data)
                    if is_new:
                        cyber_new += 1
                except Exception as e:
                    logger.error("Cyber report upsert failed %s: %s", item_id, e)
                    cyber_err += 1
            else:
                cyber_err += 1

    if latest_ts:
        update_cursor("alerts", last_timestamp=latest_ts)

    duration_ms = int((time.monotonic() - t0) * 1000)
    log_ingest("edr_alert", len([x for x in alert_list if x.get("type")=="CYCRAFT_E"]),
               edr_new, edr_err, duration_ms)
    log_ingest("cyber_report", len([x for x in alert_list if x.get("type")=="CYCRAFT_C"]),
               cyber_new, cyber_err, 0)
    logger.info(
        "Alert pull done: %d EDR (new=%d), %d Cyber (new=%d), %dms",
        len([x for x in alert_list if x.get("type")=="CYCRAFT_E"]), edr_new,
        len([x for x in alert_list if x.get("type")=="CYCRAFT_C"]), cyber_new,
        duration_ms,
    )


async def _pull_incidents() -> None:
    """Pull Incident list and upsert.

    NOTE: We do NOT use a `created_after` cursor here, because incident state
    (InProgress→Investigated→Confirmed→Closed) changes WITHOUT bumping the
    `created` timestamp. A cursor-based pull would never re-fetch state changes,
    so the local DB would show stale `state` forever.

    Instead we always re-fetch incidents within a sliding window
    (`incidents_refresh_window_days`, default 30 days). `upsert_incident()`
    dedupes by uuid and updates mutable fields (state, note, graph_summary)
    on existing rows.
    """
    from backend.core.database import upsert_incident, log_ingest
    from backend.integrations.xcockpit_client import xcockpit_client

    t0 = time.monotonic()
    refresh_days = getattr(settings.xcockpit, "incidents_refresh_window_days", 30)
    since_dt = datetime.now(timezone.utc) - timedelta(days=refresh_days)
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%S")

    offset = 0
    total_new = total_err = total_fetched = total_updated = 0

    while True:
        result = await xcockpit_client.get_incident_list(since, offset=offset, limit=50)
        incidents = result["results"]
        total_fetched += len(incidents)

        for inc in incidents:
            try:
                is_new = upsert_incident(inc)
                if is_new:
                    total_new += 1
                else:
                    total_updated += 1
            except Exception as e:
                logger.error("Incident upsert failed: %s", e)
                total_err += 1

        if not result["has_next"] or not incidents:
            break
        offset += 50

    duration_ms = int((time.monotonic() - t0) * 1000)
    log_ingest("incident", total_fetched, total_new, total_err, duration_ms)
    if total_fetched:
        logger.info(
            "Incident pull: %d fetched (new=%d, refreshed=%d, errors=%d), %dms",
            total_fetched, total_new, total_updated, total_err, duration_ms,
        )


async def _pull_activity_logs() -> None:
    """Pull activity logs from XCockpit."""
    from backend.core.database import update_cursor, upsert_activity_log, log_ingest
    from backend.integrations.xcockpit_client import xcockpit_client

    t0 = time.monotonic()
    stime = _cursor_or_default("activity_logs", default_hours_back=24)
    etime = _now_iso()

    offset = 0
    total_new = total_fetched = 0
    latest_ts: str | None = None

    while True:
        result = await xcockpit_client.get_activity_logs(stime, etime=etime, source="xcockpit",
                                                          offset=offset, limit=50)
        logs = result["results"]
        total_fetched += len(logs)

        for log_entry in logs:
            log_time = log_entry.get("time", "")
            if not latest_ts or log_time > latest_ts:
                latest_ts = log_time
            try:
                upsert_activity_log(log_entry)
                total_new += 1
            except Exception as e:
                logger.error("Activity log insert failed: %s", e)

        if not result["has_next"] or not logs:
            break
        offset += 50

    if latest_ts:
        update_cursor("activity_logs", last_timestamp=latest_ts)

    duration_ms = int((time.monotonic() - t0) * 1000)
    log_ingest("activity_log", total_fetched, total_new, 0, duration_ms)


async def _run_alert_evaluation() -> None:
    from backend.core.alert_engine import evaluate_alerts
    await evaluate_alerts()


async def _run_retention_cleanup() -> None:
    from backend.core import database as db
    conn = db.get_conn()
    days = settings.database.retention_days
    conn.execute(f"DELETE FROM edr_alerts WHERE ingested_at < now() - INTERVAL '{days} days'")
    conn.execute(f"DELETE FROM cyber_reports WHERE ingested_at < now() - INTERVAL '{days} days'")
    conn.execute(f"DELETE FROM activity_logs WHERE ingested_at < now() - INTERVAL '{days} days'")
    logger.info("Retention cleanup done (retention=%d days)", days)


def start_scheduler() -> None:
    global _scheduler
    _scheduler = AsyncIOScheduler()
    interval = settings.xcockpit.pull_interval_seconds

    _scheduler.add_job(_pull_alerts, IntervalTrigger(seconds=interval),
                       id="pull_alerts", max_instances=1, replace_existing=True)
    _scheduler.add_job(_pull_incidents, IntervalTrigger(seconds=interval),
                       id="pull_incidents", max_instances=1, replace_existing=True)
    _scheduler.add_job(_pull_activity_logs, IntervalTrigger(seconds=interval * 5),
                       id="pull_activity_logs", max_instances=1, replace_existing=True)
    _scheduler.add_job(_run_alert_evaluation, IntervalTrigger(seconds=60),
                       id="alert_eval", max_instances=1, replace_existing=True)
    _scheduler.add_job(_run_retention_cleanup, "cron", hour=3, minute=0,
                       id="retention", replace_existing=True)

    _scheduler.start()
    logger.info("Scheduler started (pull interval: %ds)", interval)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)


async def trigger_pull_now() -> dict:
    """Manually trigger all pull jobs."""
    await _pull_alerts()
    await _pull_incidents()
    return {"status": "triggered", "message": "Alert + Incident pull completed"}
