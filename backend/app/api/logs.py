from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.log_event import LogEvent
from app.schemas.log_event import LogEventOut

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("", response_model=list[LogEventOut])
def list_logs(
    log_type: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    user: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[LogEvent]:
    q = db.query(LogEvent)
    if log_type:
        q = q.filter(LogEvent.log_type == log_type)
    if hostname:
        q = q.filter(LogEvent.hostname == hostname)
    if user:
        q = q.filter(LogEvent.user == user)
    return q.order_by(LogEvent.timestamp.desc()).offset(offset).limit(limit).all()
