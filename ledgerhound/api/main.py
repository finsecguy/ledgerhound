"""FastAPI app: the dashboard's backend.

Dev mode (`lh serve --reload`, Vite on 5173) needs CORS open to the Vite
dev server; prod mode (`lh serve`, no `--reload`) serves the built
`web/dist/` as static files from this same process, so CORS is a no-op
there (same origin) but harmless to leave configured.

No authentication — this runs locally against your own database, the
same trust boundary the CLI already has. A public deployment would need
auth added in front of this app before exposing it.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ledgerhound.api.routers import assessments, campaigns, config, graph, reports, stats

WEB_DIST_DIR = Path(__file__).resolve().parent.parent.parent / "web" / "dist"

DEV_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


def create_app() -> FastAPI:
    """Build the FastAPI app. If `web/dist/` exists (a completed `npm run
    build`), it's served from this same process in prod; in dev, that
    directory doesn't exist yet (Vite's dev server serves the frontend
    instead, proxying API requests here), so nothing frontend-related is
    registered at all — no separate "prod mode" flag needed."""
    app = FastAPI(title="Ledgerhound Dashboard API", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=DEV_CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(campaigns.router)
    app.include_router(graph.router)
    app.include_router(assessments.router)
    app.include_router(assessments.attack_router)
    app.include_router(reports.router)
    app.include_router(reports.feed_router)
    app.include_router(stats.router)
    app.include_router(config.router)

    if WEB_DIST_DIR.is_dir():
        assets_dir = WEB_DIST_DIR / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="web-assets")

        # A plain StaticFiles(html=True) mount only auto-serves
        # index.html for "/" and directory-like paths — a client-side
        # route like /campaigns/LH-2026-001 doesn't correspond to a real
        # file, so a direct visit or refresh 404s. This catch-all (routed
        # last, so every /api/... route above still wins its own match)
        # serves the real file when one exists (favicon, etc.) and falls
        # back to index.html otherwise, letting React Router take over.
        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str) -> FileResponse:
            # An unmatched /api/... path is a real 404 (a typo'd or
            # removed endpoint), not a client-side route — falling back
            # to index.html here would silently turn a broken API call
            # into a confusing 200 of the SPA shell instead of a clear
            # error.
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404, detail=f"No such API route: /{full_path}")
            candidate = WEB_DIST_DIR / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            index_path = WEB_DIST_DIR / "index.html"
            if not index_path.is_file():
                raise HTTPException(status_code=404, detail="Not found")
            return FileResponse(index_path)

    return app


# Module-level app for `uvicorn ledgerhound.api.main:app` (including `lh
# serve`'s own invocation, both with and without `--reload`).
app = create_app()
