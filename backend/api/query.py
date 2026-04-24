from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from backend.core.query_engine import execute_query
from backend.dependencies import require_auth
from backend.models.query import QueryRequest, QueryResponse

router = APIRouter()


@router.post("/query", response_model=QueryResponse)
def run_query(body: QueryRequest, _=Depends(require_auth)) -> QueryResponse:
    try:
        result = execute_query(
            spl=body.query,
            time_range=body.time_range or "-24h",
            earliest=body.earliest,
            latest=body.latest,
            limit=body.limit,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query error: {e}")
    return QueryResponse(**result)


@router.get("/events/{event_id}")
def get_event(event_id: str, _=Depends(require_auth)) -> dict:
    from backend.core.database import get_conn
    row = get_conn().execute(
        "SELECT * FROM events WHERE id = ?", [event_id]
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    conn = get_conn()
    cols = [d[0] for d in conn.execute("SELECT * FROM events WHERE id = ?", [event_id]).description]
    return dict(zip(cols, row))


@router.get("/fields")
def list_fields(_=Depends(require_auth)) -> dict:
    from backend.core.database import get_conn
    conn = get_conn()
    columns = conn.execute("DESCRIBE events").fetchall()
    fields = []
    for col in columns:
        field_name = col[0]
        try:
            card = conn.execute(
                f'SELECT COUNT(DISTINCT "{field_name}") FROM events'
            ).fetchone()[0]
        except Exception:
            card = None
        fields.append({"field": field_name, "type": col[1], "cardinality": card})
    return {"fields": fields}


@router.get("/fields/{field_name}/values")
def field_values(field_name: str, limit: int = 20, _=Depends(require_auth)) -> dict:
    from backend.core.database import get_conn
    import re
    if not re.match(r"^[A-Za-z_][\w]*$", field_name) and field_name not in ("_time", "_hash", "_indextime"):
        raise HTTPException(status_code=400, detail="Invalid field name")
    conn = get_conn()
    try:
        rows = conn.execute(
            f'SELECT "{field_name}", COUNT(*) as cnt FROM events '
            f'WHERE "{field_name}" IS NOT NULL '
            f'GROUP BY "{field_name}" ORDER BY cnt DESC LIMIT ?',
            [limit],
        ).fetchall()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"field": field_name, "values": [{"value": r[0], "count": r[1]} for r in rows]}
