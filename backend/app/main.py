from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

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

app.include_router(auth.router)
app.include_router(alerts.router, dependencies=[Depends(get_current_user)])
app.include_router(iocs.router, dependencies=[Depends(get_current_user)])
app.include_router(logs.router, dependencies=[Depends(get_current_user)])
app.include_router(mitre.router, dependencies=[Depends(get_current_user)])
app.include_router(investigations.router, dependencies=[Depends(get_current_user)])
app.include_router(response.router, dependencies=[Depends(get_current_user)])


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
