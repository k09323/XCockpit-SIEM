from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
# Serve React UI (SPA) — must be the LAST routes registered
# ---------------------------------------------------------------------------
#
# The React app uses BrowserRouter, so paths like /login, /alerts, /settings
# only exist client-side. When the user hits Refresh on /alerts, the browser
# asks the server for "/alerts" — which has no static file → 404.
#
# Fix: mount /assets for hashed Vite assets, then add a catch-all that:
#   1. Serves any real file inside the dist/ directory (favicon, vite.svg, …)
#   2. Falls back to index.html so the SPA router can take over
#
# API routes (/api/*) are registered BEFORE this block, so FastAPI matches
# them first and the catch-all only fires for non-API paths.

_static_dir = Path(settings.ui.static_dir)
if settings.ui.serve_ui and _static_dir.exists():
    _assets_dir = _static_dir / "assets"
    if _assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="assets")

    _index_html = _static_dir / "index.html"

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        # API & WS paths are matched earlier; if we still see them here they're
        # genuinely missing — return JSON 404 instead of HTML.
        if full_path.startswith(("api/", "ws/")):
            raise HTTPException(status_code=404, detail="Not Found")

        # Real file in dist/ root (favicon.ico, vite.svg, robots.txt, …)
        candidate = _static_dir / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)

        # SPA route — let React Router handle it client-side
        if _index_html.is_file():
            return FileResponse(_index_html)
        raise HTTPException(status_code=404, detail="UI not built")
