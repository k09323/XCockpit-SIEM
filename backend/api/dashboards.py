from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from backend.core.database import get_conn
from backend.core.query_engine import execute_query
from backend.dependencies import require_auth
from backend.models.dashboard import Dashboard, DashboardCreate, DashboardLayout, DashboardUpdate

router = APIRouter()


def _row_to_dashboard(row: tuple, cols: list[str]) -> Dashboard:
    d = dict(zip(cols, row))
    if isinstance(d["layout"], str):
        d["layout"] = json.loads(d["layout"])
    d["layout"] = DashboardLayout(**d["layout"])
    return Dashboard(**d)


_COLS = ["id", "name", "description", "layout", "created_at", "updated_at"]


@router.get("/", response_model=list[Dashboard])
def list_dashboards(_=Depends(require_auth)) -> list[Dashboard]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, name, description, layout, created_at, updated_at FROM dashboards ORDER BY created_at DESC"
    ).fetchall()
    return [_row_to_dashboard(r, _COLS) for r in rows]


@router.post("/", response_model=Dashboard, status_code=status.HTTP_201_CREATED)
def create_dashboard(body: DashboardCreate, _=Depends(require_auth)) -> Dashboard:
    conn = get_conn()
    layout_json = body.layout.model_dump_json()
    row = conn.execute(
        "INSERT INTO dashboards (name, description, layout) VALUES (?, ?, ?) "
        "RETURNING id, name, description, layout, created_at, updated_at",
        [body.name, body.description, layout_json],
    ).fetchone()
    return _row_to_dashboard(row, _COLS)


@router.get("/{dashboard_id}", response_model=Dashboard)
def get_dashboard(dashboard_id: str, _=Depends(require_auth)) -> Dashboard:
    conn = get_conn()
    row = conn.execute(
        "SELECT id, name, description, layout, created_at, updated_at FROM dashboards WHERE id = ?",
        [dashboard_id],
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return _row_to_dashboard(row, _COLS)


@router.put("/{dashboard_id}", response_model=Dashboard)
def update_dashboard(dashboard_id: str, body: DashboardUpdate, _=Depends(require_auth)) -> Dashboard:
    conn = get_conn()
    updates: dict = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.description is not None:
        updates["description"] = body.description
    if body.layout is not None:
        updates["layout"] = body.layout.model_dump_json()
    if updates:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(
            f"UPDATE dashboards SET {set_clause}, updated_at = now() WHERE id = ?",
            list(updates.values()) + [dashboard_id],
        )
    return get_dashboard(dashboard_id)


@router.delete("/{dashboard_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dashboard(dashboard_id: str, _=Depends(require_auth)) -> None:
    get_conn().execute("DELETE FROM dashboards WHERE id = ?", [dashboard_id])


@router.post("/{dashboard_id}/run")
def run_dashboard(dashboard_id: str, _=Depends(require_auth)) -> dict:
    dashboard = get_dashboard(dashboard_id)
    results = {}
    for panel in dashboard.layout.panels:
        try:
            result = execute_query(panel.query, time_range=panel.time_range)
            results[panel.id] = {"status": "ok", **result}
        except Exception as e:
            results[panel.id] = {"status": "error", "error": str(e)}
    return {"dashboard_id": dashboard_id, "panels": results}
