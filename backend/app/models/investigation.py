from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"), index=True)

    verdict: Mapped[str] = mapped_column(String(64))
    # Lifecycle status of this investigation run itself -- distinct from
    # Alert.status. "completed" is the only state ever persisted today
    # (a failed run isn't persisted as an Investigation row at all -- see
    # api/investigations.py), but the column exists so a future async/queued
    # investigation flow can persist "in_progress"/"failed" without a
    # schema change.
    status: Mapped[str] = mapped_column(String(16), default="completed")
    # Disposition/classification -- deterministic, evidence-based, and
    # NOT derived solely from risk_score (see services/reporting/report_builder.py).
    disposition: Mapped[str] = mapped_column(String(16), default="inconclusive")
    # "true_positive" | "false_positive" | "benign_positive" | "suspicious" | "inconclusive"
    requires_customer_validation: Mapped[bool] = mapped_column(default=False)
    report_markdown: Mapped[str] = mapped_column(Text, default="")

    # Severity of record -- always the deterministic risk engine's output,
    # never the LLM's own `severity` field from InvestigationResult.
    severity: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[float] = mapped_column(Float)
    risk_factors: Mapped[dict] = mapped_column(JSON, default=dict)

    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    atlas_techniques: Mapped[list] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    rag_sources: Mapped[list] = mapped_column(JSON, default=list)

    llm_used: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
