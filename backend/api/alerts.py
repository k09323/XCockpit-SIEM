from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from backend.core.database import get_conn
from backend.dependencies import require_auth
from backend.models.alerts import AlertIncident, AlertRule, AlertRuleCreate, AlertRuleUpdate

router = APIRouter()


# ---------------------------------------------------------------------------
# Alert Rules CRUD
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=list[AlertRule])
def list_rules(_=Depends(require_auth)) -> list[AlertRule]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, name, description, query, condition, severity, enabled, throttle_mins, created_at, updated_at "
        "FROM alert_rules ORDER BY created_at DESC"
    ).fetchall()
    cols = ["id", "name", "description", "query", "condition", "severity", "enabled", "throttle_mins", "created_at", "updated_at"]
    return [AlertRule(**dict(zip(cols, r))) for r in rows]


@router.post("/rules", response_model=AlertRule, status_code=status.HTTP_201_CREATED)
def create_rule(body: AlertRuleCreate, _=Depends(require_auth)) -> AlertRule:
    conn = get_conn()
    row = conn.execute(
        """INSERT INTO alert_rules (name, description, query, condition, severity, throttle_mins)
           VALUES (?, ?, ?, ?, ?, ?) RETURNING id, name, description, query, condition,
           severity, enabled, throttle_mins, created_at, updated_at""",
        [body.name, body.description, body.query, body.condition, body.severity, body.throttle_mins],
    ).fetchone()
    cols = ["id", "name", "description", "query", "condition", "severity", "enabled", "throttle_mins", "created_at", "updated_at"]
    return AlertRule(**dict(zip(cols, row)))


@router.get("/rules/{rule_id}", response_model=AlertRule)
def get_rule(rule_id: str, _=Depends(require_auth)) -> AlertRule:
    conn = get_conn()
    row = conn.execute(
        "SELECT id, name, description, query, condition, severity, enabled, throttle_mins, created_at, updated_at "
        "FROM alert_rules WHERE id = ?", [rule_id]
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    cols = ["id", "name", "description", "query", "condition", "severity", "enabled", "throttle_mins", "created_at", "updated_at"]
    return AlertRule(**dict(zip(cols, row)))


@router.put("/rules/{rule_id}", response_model=AlertRule)
def update_rule(rule_id: str, body: AlertRuleUpdate, _=Depends(require_auth)) -> AlertRule:
    conn = get_conn()
    updates = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if not updates:
        return get_rule(rule_id)
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [rule_id]
    conn.execute(
        f"UPDATE alert_rules SET {set_clause}, updated_at = now() WHERE id = ?", vals
    )
    return get_rule(rule_id)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: str, _=Depends(require_auth)) -> None:
    get_conn().execute("DELETE FROM alert_rules WHERE id = ?", [rule_id])


@router.patch("/rules/{rule_id}/toggle", response_model=AlertRule)
def toggle_rule(rule_id: str, _=Depends(require_auth)) -> AlertRule:
    conn = get_conn()
    conn.execute(
        "UPDATE alert_rules SET enabled = NOT enabled, updated_at = now() WHERE id = ?", [rule_id]
    )
    return get_rule(rule_id)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.get("/incidents", response_model=list[AlertIncident])
def list_incidents(status_filter: Optional[str] = None, _=Depends(require_auth)) -> list[AlertIncident]:
    conn = get_conn()
    sql = (
        "SELECT i.id, i.rule_id, r.name as rule_name, i.triggered_at, i.resolved_at, "
        "i.metric_value, i.status, i.details "
        "FROM alert_incidents i LEFT JOIN alert_rules r ON i.rule_id = r.id"
    )
    params = []
    if status_filter:
        sql += " WHERE i.status = ?"
        params.append(status_filter)
    sql += " ORDER BY i.triggered_at DESC LIMIT 200"
    rows = conn.execute(sql, params).fetchall()
    cols = ["id", "rule_id", "rule_name", "triggered_at", "resolved_at", "metric_value", "status", "details"]
    result = []
    for r in rows:
        d = dict(zip(cols, r))
        if isinstance(d["details"], str):
            d["details"] = json.loads(d["details"])
        result.append(AlertIncident(**d))
    return result


@router.get("/incidents/{incident_id}", response_model=AlertIncident)
def get_incident(incident_id: str, _=Depends(require_auth)) -> AlertIncident:
    conn = get_conn()
    row = conn.execute(
        "SELECT i.id, i.rule_id, r.name as rule_name, i.triggered_at, i.resolved_at, "
        "i.metric_value, i.status, i.details "
        "FROM alert_incidents i LEFT JOIN alert_rules r ON i.rule_id = r.id WHERE i.id = ?",
        [incident_id],
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    cols = ["id", "rule_id", "rule_name", "triggered_at", "resolved_at", "metric_value", "status", "details"]
    d = dict(zip(cols, row))
    if isinstance(d["details"], str):
        d["details"] = json.loads(d["details"])
    return AlertIncident(**d)


@router.post("/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: str, _=Depends(require_auth)) -> dict:
    get_conn().execute(
        "UPDATE alert_incidents SET status = 'acknowledged' WHERE id = ?", [incident_id]
    )
    return {"status": "acknowledged"}


@router.post("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, _=Depends(require_auth)) -> dict:
    get_conn().execute(
        "UPDATE alert_incidents SET status = 'resolved', resolved_at = now() WHERE id = ?",
        [incident_id],
    )
    return {"status": "resolved"}
