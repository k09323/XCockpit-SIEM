from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query

from backend.core.database import get_conn
from backend.core.query_engine import execute_query
from backend.dependencies import require_auth

router = APIRouter()


@router.get("/search")
def simple_search(
    q: Optional[str] = Query(None, description="Free text search"),
    field: Optional[str] = Query(None),
    value: Optional[str] = Query(None),
    time_range: str = Query("-24h"),
    from_: int = Query(0, alias="from"),
    size: int = Query(50, le=500),
    sort: str = Query("_time:desc"),
    _=Depends(require_auth),
) -> dict:
    # Build a simple SPL from the GET params
    parts: list[str] = []
    if field and value:
        parts.append(f'{field}="{value}"')
    if q:
        parts.append(f'"{q}"')

    sort_field, sort_dir = sort.rsplit(":", 1) if ":" in sort else (sort, "desc")
    spl_sort = f"-{sort_field}" if sort_dir == "desc" else f"+{sort_field}"

    spl = " ".join(parts) if parts else "*"
    spl += f" | sort {spl_sort} | head {from_ + size}"

    result = execute_query(spl, time_range=time_range)
    rows = result["rows"][from_:]

    return {
        "hits": rows,
        "columns": result["columns"],
        "total": result["total"],
        "from": from_,
        "size": size,
    }
