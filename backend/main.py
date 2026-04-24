from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api import alerts, auth, dashboards, ingest, query, search, system
from backend.config import settings
from backend.core.database import init_db
from backend.core.pipeline import subscribe_live, unsubscribe_live
from backend.core.scheduler import start_scheduler, stop_scheduler

logging.basicConfig(level=settings.server.log_level.upper())
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_scheduler()
    logger.info("XCockpit SIEM started on port %d", settings.server.port)
    yield
    stop_scheduler()
    logger.info("XCockpit SIEM stopped")


app = FastAPI(
    title="XCockpit SIEM",
    version="1.0.0",
    description="Splunk-like security analytics platform for XCockpit",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(auth.router,       prefix="/api/auth",       tags=["auth"])
app.include_router(ingest.router,     prefix="/api/ingest",     tags=["ingest"])
app.include_router(query.router,      prefix="/api",            tags=["query"])
app.include_router(search.router,     prefix="/api",            tags=["search"])
app.include_router(dashboards.router, prefix="/api/dashboards", tags=["dashboards"])
app.include_router(alerts.router,     prefix="/api/alerts",     tags=["alerts"])
app.include_router(system.router,     prefix="/api/system",     tags=["system"])


# ---------------------------------------------------------------------------
# WebSocket live tail
# ---------------------------------------------------------------------------

@app.websocket("/ws/tail")
async def live_tail(ws: WebSocket, filter: str = ""):
    await ws.accept()
    q = subscribe_live()
    try:
        while True:
            try:
                event = q.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.5)
                continue
            # Optional filter: check if any field matches
            if filter:
                ev_str = json.dumps(event, default=str).lower()
                if filter.lower() not in ev_str:
                    continue
            await ws.send_json(event, mode="text")
    except WebSocketDisconnect:
        unsubscribe_live(q)


# ---------------------------------------------------------------------------
# Serve React UI (if built)
# ---------------------------------------------------------------------------

_static_dir = Path(settings.ui.static_dir)
if settings.ui.serve_ui and _static_dir.exists():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="ui")
