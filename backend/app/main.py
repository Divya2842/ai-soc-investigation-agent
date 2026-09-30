from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse

from app.api import alerts, auth, investigations, iocs, logs, mitre, response
from app.config.settings import settings
from app.database.session import init_db
from app.security.auth import get_current_user


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AI-Powered SOC Investigation & IOC Enrichment Agent",
    description=(
        "Evidence-driven SOC investigation backend. Deterministic IOC "
        "extraction, enrichment, MITRE mapping, and risk scoring; LLM "
        "reasoning (Groq) is used only to explain evidence, never to "
        "invent it."
    ),
    version="0.1.0-milestone1",
    lifespan=lifespan,
)


# ============================================================
# API ROUTES
# ============================================================

app.include_router(auth.router)
app.include_router(
    alerts.router,
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    iocs.router,
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    logs.router,
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    mitre.router,
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    investigations.router,
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    response.router,
    dependencies=[Depends(get_current_user)],
)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health", tags=["meta"])
def health() -> dict:
    return {
        "status": "ok",
        "groq_configured": settings.groq_configured,
        "log_source": settings.log_source,
        "note": (
            "groq_configured=false means investigations use the "
            "deterministic-only fallback summary instead of an LLM-authored "
            "one; every other capability (extraction, enrichment, MITRE "
            "mapping, risk scoring, RAG, response recommendations) is fully "
            "functional either way."
        ),
    }


# ============================================================
# REACT FRONTEND
# ============================================================

# Docker copies the Vite production build to:
# /app/frontend/dist
FRONTEND_DIST = Path("/app/frontend/dist")


@app.get("/", include_in_schema=False)
async def serve_frontend():
    """
    Serve the React application from the same FastAPI service.
    """

    index_file = FRONTEND_DIST / "index.html"

    if not index_file.exists():
        return {
            "message": "SOC Investigation Agent API",
            "frontend": "Frontend build not found.",
            "docs": "/docs",
        }

    return FileResponse(index_file)


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_react_routes(full_path: str):
    """
    Support React client-side routing.

    Examples:
        /login
        /register
        /forgot-password
        /dashboard
        /investigations/123
    """

    # If the requested path is an actual frontend file
    # (JS, CSS, images, etc.), return that file.
    requested_file = FRONTEND_DIST / full_path

    if requested_file.is_file():
        return FileResponse(requested_file)

    # Otherwise return index.html and allow React Router
    # to handle the route.
    index_file = FRONTEND_DIST / "index.html"

    if index_file.exists():
        return FileResponse(index_file)

    return {
        "detail": "Frontend build not found.",
        "docs": "/docs",
    }