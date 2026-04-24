from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status

from backend.config import settings
from backend.core.pipeline import process_batch
from backend.models.events import IngestBatch, IngestResponse

router = APIRouter()


def _verify_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    expected = settings.xcockpit.push_api_key
    if not expected:
        return  # API key auth disabled when not configured
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


@router.post("/events", response_model=IngestResponse)
async def ingest_events(
    batch: IngestBatch,
    _: None = Depends(_verify_api_key),
) -> IngestResponse:
    result = await process_batch(
        batch.events,
        source=batch.source,
        sourcetype=batch.sourcetype,
        batch_id=batch.batch_id,
    )
    return IngestResponse(
        accepted=result["accepted"],
        rejected=result["rejected"],
        batch_id=result["batch_id"],
        errors=result["errors"][:10],  # cap error list
    )


@router.get("/status")
def ingest_status() -> dict:
    from backend.core.database import get_conn
    conn = get_conn()
    rows = conn.execute(
        "SELECT source, batch_id, events_count, errors_count, duration_ms, ingested_at "
        "FROM ingest_log ORDER BY ingested_at DESC LIMIT 20"
    ).fetchall()
    cols = ["source", "batch_id", "events_count", "errors_count", "duration_ms", "ingested_at"]
    return {"batches": [dict(zip(cols, r)) for r in rows]}
