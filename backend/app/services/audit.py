from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, Session

from app.database.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    actor: Mapped[str] = mapped_column(String(32))  # "system" | "llm" | a username
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    investigation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tool_called: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_input: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_result: Mapped[dict] = mapped_column(JSON, default=dict)
    decision: Mapped[str | None] = mapped_column(String(256), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(512), nullable=True)


def record(
    db: Session,
    *,
    actor: str,
    alert_id: str | None = None,
    investigation_id: str | None = None,
    tool_called: str | None = None,
    tool_input: dict | None = None,
    tool_result: dict | None = None,
    decision: str | None = None,
    notes: str | None = None,
) -> AuditLogEntry:
    entry = AuditLogEntry(
        actor=actor,
        alert_id=alert_id,
        investigation_id=investigation_id,
        tool_called=tool_called,
        tool_input=tool_input or {},
        tool_result=tool_result or {},
        decision=decision,
        notes=notes,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
