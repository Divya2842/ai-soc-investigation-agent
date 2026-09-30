from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LogEvent(Base):
    """A single simulated SOC log record (any of the 8 supported log types)."""

    __tablename__ = "raw_log_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    log_type: Mapped[str] = mapped_column(String(32), index=True)
    # windows_security | powershell | auth | network | endpoint | dns | process | firewall
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
