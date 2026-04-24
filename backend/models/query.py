from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class QueryRequest(BaseModel):
    query: str
    time_range: Optional[str] = "-24h"
    earliest: Optional[str] = None
    latest: Optional[str] = None
    limit: int = Field(default=1000, le=10000)


class QueryResponse(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    total: int
    duration_ms: int
    query_id: Optional[str] = None
    sql: Optional[str] = None


class SearchRequest(BaseModel):
    q: Optional[str] = None
    field: Optional[str] = None
    value: Optional[str] = None
    from_: int = Field(default=0, alias="from")
    size: int = Field(default=50, le=500)
    sort: str = "_time:desc"
    time_range: str = "-24h"
