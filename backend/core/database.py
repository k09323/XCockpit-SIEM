from __future__ import annotations

"""DuckDB connection management and schema for XCockpit SIEM.

Tables:
  edr_alerts          — CYCRAFT_E alerts (malware/threat detections)
  cyber_reports       — CYCRAFT_C reports (Cyber Situation Reports)
  incidents           — XCockpit incidents
  incident_events     — Raw events inside an incident
  activity_logs       — XCockpit/Xensor activity logs
  pull_cursors        — tracks last-seen timestamps per data type
  alert_rules         — SIEM alert rules
  alert_incidents     — triggered SIEM alert incidents
  dashboards          — saved dashboard configurations
  saved_searches      — saved SPL queries
  users               — SIEM users
  refresh_tokens      — JWT refresh tokens
  ingest_log          — pull job stats
"""

import json
import logging
import threading
from pathlib import Path
from typing import Any

import duckdb

from backend.config import settings

logger = logging.getLogger(__name__)

_local = threading.local()
_db_path: str = ""


def _get_conn() -> duckdb.DuckDBPyConnection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = duckdb.connect(_db_path)
        _local.conn.execute(f"SET memory_limit='{settings.database.max_memory}'")
        _local.conn.execute(f"SET threads={settings.database.threads}")
    return _local.conn


def get_conn() -> duckdb.DuckDBPyConnection:
    return _get_conn()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE SEQUENCE IF NOT EXISTS ingest_log_seq;

-- ── EDR Alerts (CYCRAFT_E) ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS edr_alerts (
    id                  VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id            VARCHAR UNIQUE NOT NULL,   -- XCockpit alert id
    report_type         VARCHAR DEFAULT 'CYCRAFT_E',
    report_time         TIMESTAMP,                 -- when XCockpit created the alert
    severity            INTEGER,                   -- 1-10
    customer_name       VARCHAR,
    date_start          TIMESTAMP,
    date_end            TIMESTAMP,
    compromised_computers INTEGER DEFAULT 0,
    scanned_endpoints   INTEGER DEFAULT 0,
    malware_count       INTEGER DEFAULT 0,
    network_count       INTEGER DEFAULT 0,
    campaigns           JSON,                      -- full campaigns array
    raw                 JSON NOT NULL,             -- full API response
    ingested_at         TIMESTAMP DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_edr_alerts_time ON edr_alerts (report_time);
CREATE INDEX IF NOT EXISTS idx_edr_alerts_severity ON edr_alerts (severity);

-- ── Cyber Situation Reports (CYCRAFT_C) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS cyber_reports (
    id                  VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id           VARCHAR UNIQUE NOT NULL,   -- XCockpit report id
    report_type         VARCHAR DEFAULT 'CYCRAFT_C',
    report_time         TIMESTAMP,
    severity            INTEGER,
    customer_name       VARCHAR,
    start_date          DATE,
    end_date            DATE,
    scanned_endpoints   INTEGER DEFAULT 0,
    total_computers     INTEGER DEFAULT 0,
    suspicious_endpoints INTEGER DEFAULT 0,
    suspicious_files    INTEGER DEFAULT 0,
    suspicious_c2_count INTEGER DEFAULT 0,
    activities          INTEGER DEFAULT 0,
    summary             JSON,
    suspicious_file_list JSON,
    suspicious_c2_list  JSON,
    endpoints           JSON,
    raw                 JSON NOT NULL,
    ingested_at         TIMESTAMP DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cyber_reports_time ON cyber_reports (report_time);

-- ── Incidents ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id                  VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    uuid                VARCHAR UNIQUE NOT NULL,   -- XCockpit incident UUID
    title               VARCHAR,
    created             TIMESTAMP,
    computer_id         VARCHAR,
    computer_name       VARCHAR,
    computer_os_type    VARCHAR,
    ip                  VARCHAR[],
    group_name          VARCHAR,
    state               INTEGER,                   -- 0=InProgress 1=Investigated 2=Confirmed 3=Closed 4=Merged 5=Reopened
    tags                VARCHAR[],
    edr_alert_ids       BIGINT[],
    total_event_count   INTEGER DEFAULT 0,
    alerted_event_count INTEGER DEFAULT 0,
    first_event_time    TIMESTAMP,
    last_event_time     TIMESTAMP,
    note                TEXT,
    graph_summary       TEXT,
    raw                 JSON NOT NULL,
    ingested_at         TIMESTAMP DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created);
CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents (state);
CREATE INDEX IF NOT EXISTS idx_incidents_computer ON incidents (computer_name);

-- ── Activity Logs ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_logs (
    id                  VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    log_time            TIMESTAMP NOT NULL,
    account             VARCHAR,
    ip                  VARCHAR,
    action              VARCHAR,
    codename            VARCHAR,
    description         TEXT,
    source              VARCHAR,                   -- xcockpit or xensor
    ingested_at         TIMESTAMP DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_logs (log_time);

-- ── Pull Cursors ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pull_cursors (
    endpoint            VARCHAR PRIMARY KEY,
    last_id             VARCHAR,
    last_timestamp      TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT now()
);

-- ── Ingest Log ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingest_log (
    id              BIGINT PRIMARY KEY DEFAULT nextval('ingest_log_seq'),
    data_type       VARCHAR NOT NULL,   -- edr_alert / cyber_report / incident / activity_log
    fetched_count   INTEGER DEFAULT 0,
    new_count       INTEGER DEFAULT 0,
    error_count     INTEGER DEFAULT 0,
    duration_ms     INTEGER,
    ingested_at     TIMESTAMP DEFAULT now()
);

-- ── SIEM Alert Rules ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
    id              VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR NOT NULL UNIQUE,
    description     TEXT,
    query           TEXT NOT NULL,
    condition       VARCHAR NOT NULL,
    severity        VARCHAR NOT NULL DEFAULT 'medium',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    throttle_mins   INTEGER DEFAULT 60,
    created_at      TIMESTAMP DEFAULT now(),
    updated_at      TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_incidents (
    id              VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         VARCHAR NOT NULL,
    triggered_at    TIMESTAMP NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMP,
    metric_value    DOUBLE,
    status          VARCHAR DEFAULT 'open',
    details         JSON
);

-- ── Dashboards & Saved Searches ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dashboards (
    id              VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR NOT NULL UNIQUE,
    description     TEXT,
    layout          JSON NOT NULL DEFAULT '{"panels": []}',
    created_at      TIMESTAMP DEFAULT now(),
    updated_at      TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS saved_searches (
    id              VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR NOT NULL UNIQUE,
    query           TEXT NOT NULL,
    time_range      VARCHAR DEFAULT '-24h',
    created_at      TIMESTAMP DEFAULT now()
);

-- ── Users & Auth ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR NOT NULL UNIQUE,
    password_hash   VARCHAR NOT NULL,
    role            VARCHAR DEFAULT 'analyst',
    created_at      TIMESTAMP DEFAULT now(),
    last_login      TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash      VARCHAR PRIMARY KEY,
    user_id         VARCHAR NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    created_at      TIMESTAMP DEFAULT now()
);
"""


def init_db() -> None:
    global _db_path
    _db_path = settings.database.path
    Path(_db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = _get_conn()
    conn.execute(_SCHEMA_SQL)
    logger.info("Database initialized at %s", _db_path)
    _seed_default_user(conn)
    _seed_alert_rules(conn)


def _seed_default_user(conn: duckdb.DuckDBPyConnection) -> None:
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return
    import bcrypt
    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ["admin", pw_hash, "admin"],
    )
    logger.warning("Seeded default admin user — change password immediately!")


def _seed_alert_rules(conn: duckdb.DuckDBPyConnection) -> None:
    import yaml
    rules_path = Path(__file__).parent.parent.parent / "config" / "alert_rules.yaml"
    if not rules_path.exists():
        return
    with open(rules_path) as f:
        data = yaml.safe_load(f)
    for rule in data.get("rules", []):
        if conn.execute("SELECT COUNT(*) FROM alert_rules WHERE name=?", [rule["name"]]).fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO alert_rules (name, description, query, condition, severity, throttle_mins) VALUES (?,?,?,?,?,?)",
                [rule["name"], rule.get("description",""), rule["query"], rule["condition"], rule.get("severity","medium"), rule.get("throttle_mins",60)],
            )


# ---------------------------------------------------------------------------
# Pull cursor helpers
# ---------------------------------------------------------------------------

def get_cursor(endpoint: str) -> dict:
    row = _get_conn().execute(
        "SELECT last_id, last_timestamp FROM pull_cursors WHERE endpoint=?", [endpoint]
    ).fetchone()
    return {"last_id": row[0], "last_timestamp": row[1]} if row else {"last_id": None, "last_timestamp": None}


def update_cursor(endpoint: str, last_id=None, last_timestamp=None) -> None:
    _get_conn().execute(
        """INSERT INTO pull_cursors (endpoint, last_id, last_timestamp, updated_at)
           VALUES (?,?,?,now())
           ON CONFLICT(endpoint) DO UPDATE SET
               last_id=excluded.last_id,
               last_timestamp=excluded.last_timestamp,
               updated_at=now()""",
        [endpoint, last_id, last_timestamp],
    )


# ---------------------------------------------------------------------------
# Ingest helpers
# ---------------------------------------------------------------------------

def upsert_edr_alert(alert: dict[str, Any]) -> bool:
    """Insert EDR alert, skip if already exists. Returns True if new."""
    conn = _get_conn()
    alert_id = str(alert.get("_xcockpit_alert_id") or alert.get("ReportID", ""))
    if not alert_id:
        return False
    existing = conn.execute("SELECT COUNT(*) FROM edr_alerts WHERE alert_id=?", [alert_id]).fetchone()[0]
    if existing:
        return False

    summary = alert.get("Summary", {})
    conn.execute(
        """INSERT INTO edr_alerts
           (alert_id, report_time, severity, customer_name, date_start, date_end,
            compromised_computers, scanned_endpoints, malware_count, network_count,
            campaigns, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            alert_id,
            alert.get("ReportTime"),
            summary.get("ReportSeverity"),
            alert.get("CustomerName"),
            summary.get("DateStart") or alert.get("DateStart"),
            summary.get("DateEnd") or alert.get("DateEnd"),
            summary.get("CompromisedComputerCnt", 0),
            summary.get("ScannedEndpointCnt", 0),
            summary.get("MalwareCnt", 0),
            summary.get("Networks", 0),
            json.dumps(alert.get("Campaigns", [])),
            json.dumps(alert),
        ],
    )
    return True


def upsert_cyber_report(report: dict[str, Any]) -> bool:
    """Insert Cyber Situation Report. Returns True if new."""
    conn = _get_conn()
    report_id = str(report.get("_xcockpit_report_id") or report.get("ReportID", ""))
    if not report_id:
        return False
    if conn.execute("SELECT COUNT(*) FROM cyber_reports WHERE report_id=?", [report_id]).fetchone()[0]:
        return False

    summary = report.get("Summary", {})
    conn.execute(
        """INSERT INTO cyber_reports
           (report_id, report_time, severity, customer_name, start_date, end_date,
            scanned_endpoints, total_computers, suspicious_endpoints, suspicious_files,
            suspicious_c2_count, activities, summary, suspicious_file_list,
            suspicious_c2_list, endpoints, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            report_id,
            report.get("ReportTime"),
            summary.get("Severity"),
            summary.get("Customer") or report.get("CustomerName"),
            summary.get("StartDate"),
            summary.get("EndDate"),
            summary.get("ScannedEndpoints", 0),
            summary.get("TotalComputerCnt", 0),
            summary.get("SuspiciousEndpoints", 0),
            summary.get("SuspiciousFiles", 0),
            summary.get("SuspiciousC2Cnt", 0),
            summary.get("Activities", 0),
            json.dumps(summary),
            json.dumps(report.get("SuspiciousFile", [])),
            json.dumps(report.get("SuspiciousC2", [])),
            json.dumps(report.get("Endpoints", [])),
            json.dumps(report),
        ],
    )
    return True


def upsert_incident(inc: dict[str, Any]) -> bool:
    """Insert/update incident. Returns True if new."""
    conn = _get_conn()
    uuid = inc.get("uuid", "")
    if not uuid:
        return False
    existing = conn.execute("SELECT COUNT(*) FROM incidents WHERE uuid=?", [uuid]).fetchone()[0]
    if existing:
        # Update mutable fields (state, note)
        conn.execute(
            "UPDATE incidents SET state=?, note=?, graph_summary=?, raw=? WHERE uuid=?",
            [inc.get("state"), inc.get("note"), inc.get("graph_summary"), json.dumps(inc), uuid],
        )
        return False

    created = inc.get("created")
    conn.execute(
        """INSERT INTO incidents
           (uuid, title, created, computer_id, computer_name, computer_os_type,
            ip, group_name, state, tags, edr_alert_ids, total_event_count,
            alerted_event_count, first_event_time, last_event_time, note,
            graph_summary, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            uuid,
            inc.get("title"),
            created,
            inc.get("computer_id"),
            inc.get("computer_name"),
            inc.get("computer_os_type"),
            inc.get("ip", []),
            inc.get("group"),
            inc.get("state"),
            inc.get("tags", []),
            inc.get("edr_alert_ids", []),
            inc.get("total_event_count", 0),
            inc.get("alerted_event_count", 0),
            inc.get("first_event_time"),
            inc.get("last_event_time"),
            inc.get("note"),
            inc.get("graph_summary"),
            json.dumps(inc),
        ],
    )
    return True


def upsert_activity_log(log: dict[str, Any]) -> bool:
    """Insert activity log entry."""
    conn = _get_conn()
    time_val = log.get("time")
    account = log.get("account", "")
    action = log.get("action", "")
    # Use time+account+action as dedup key
    import hashlib
    dedup = hashlib.sha256(f"{time_val}:{account}:{action}".encode()).hexdigest()
    # We can't easily dedup without a unique index; skip if too close
    conn.execute(
        """INSERT INTO activity_logs (log_time, account, ip, action, codename, description, source)
           VALUES (?,?,?,?,?,?,?)""",
        [
            time_val,
            account,
            log.get("ip"),
            action,
            log.get("codename"),
            log.get("description"),
            log.get("source"),
        ],
    )
    return True


def log_ingest(data_type: str, fetched: int, new: int, errors: int, duration_ms: int) -> None:
    _get_conn().execute(
        "INSERT INTO ingest_log (data_type, fetched_count, new_count, error_count, duration_ms) VALUES (?,?,?,?,?)",
        [data_type, fetched, new, errors, duration_ms],
    )


# ---------------------------------------------------------------------------
# Alert engine helpers
# ---------------------------------------------------------------------------

def get_enabled_alert_rules() -> list[dict]:
    rows = _get_conn().execute(
        "SELECT id, name, query, condition, severity, throttle_mins FROM alert_rules WHERE enabled=true"
    ).fetchall()
    return [dict(zip(["id","name","query","condition","severity","throttle_mins"], r)) for r in rows]


def get_last_incident_time(rule_id: str):
    row = _get_conn().execute(
        "SELECT MAX(triggered_at) FROM alert_incidents WHERE rule_id=?", [rule_id]
    ).fetchone()
    return row[0] if row else None


def create_incident(rule_id: str, metric_value: float, details: dict) -> str:
    row = _get_conn().execute(
        "INSERT INTO alert_incidents (rule_id, metric_value, details) VALUES (?,?,?) RETURNING id",
        [rule_id, metric_value, json.dumps(details)],
    ).fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# System stats
# ---------------------------------------------------------------------------

def get_db_stats() -> dict:
    conn = _get_conn()
    edr_count = conn.execute("SELECT COUNT(*) FROM edr_alerts").fetchone()[0]
    cyber_count = conn.execute("SELECT COUNT(*) FROM cyber_reports").fetchone()[0]
    incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    db_size = Path(_db_path).stat().st_size if Path(_db_path).exists() else 0
    return {
        "edr_alerts": edr_count,
        "cyber_reports": cyber_count,
        "incidents": incident_count,
        "db_size_mb": round(db_size / 1024 / 1024, 2),
    }
