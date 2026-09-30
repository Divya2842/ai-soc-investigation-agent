from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base
from app.models.alert import Alert


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IOC(Base):
    __tablename__ = "iocs"

    __table_args__ = (
        UniqueConstraint(
            "alert_id",
            "ioc_type",
            "value",
            name="uq_alert_ioc",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_uuid,
    )

    alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("alerts.id"),
    )

    ioc_type: Mapped[str] = mapped_column(
        String(16)
    )

    value: Mapped[str] = mapped_column(
        String(512)
    )

    first_extracted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )

    alert: Mapped["Alert"] = relationship(
        "Alert",
        back_populates="iocs",
    )