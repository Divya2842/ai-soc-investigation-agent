"""
LogSource abstraction. `LocalLogSource` is fully functional against the
seeded `raw_log_events` table. `SentinelLogSource` is a documented
placeholder only -- see docs/SENTINEL_INTEGRATION.md.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.log_event import LogEvent


@dataclass(frozen=True)
class LogQuery:
    log_type: str | None = None
    hostname: str | None = None
    user: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    limit: int = 100


class LogSource(ABC):
    @abstractmethod
    def search_logs(self, query: LogQuery) -> list[dict]: ...

    @abstractmethod
    def get_user_activity(self, user: str, window: timedelta, around: datetime) -> list[dict]: ...

    @abstractmethod
    def get_host_activity(self, hostname: str, window: timedelta, around: datetime) -> list[dict]: ...


class LocalLogSource(LogSource):
    def __init__(self, db: Session):
        self._db = db

    def _to_dict(self, row: LogEvent) -> dict:
        return {
            "log_type": row.log_type,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "hostname": row.hostname,
            "user": row.user,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "payload": row.payload,
        }

    def search_logs(self, query: LogQuery) -> list[dict]:
        q = self._db.query(LogEvent)
        if query.log_type:
            q = q.filter(LogEvent.log_type == query.log_type)
        if query.hostname:
            q = q.filter(LogEvent.hostname == query.hostname)
        if query.user:
            q = q.filter(LogEvent.user == query.user)
        if query.start:
            q = q.filter(LogEvent.timestamp >= query.start)
        if query.end:
            q = q.filter(LogEvent.timestamp <= query.end)
        rows = q.order_by(LogEvent.timestamp.asc()).limit(query.limit).all()
        return [self._to_dict(r) for r in rows]

    def get_user_activity(self, user: str, window: timedelta, around: datetime) -> list[dict]:
        return self.search_logs(
            LogQuery(user=user, start=around - window, end=around + window, limit=200)
        )

    def get_host_activity(self, hostname: str, window: timedelta, around: datetime) -> list[dict]:
        return self.search_logs(
            LogQuery(hostname=hostname, start=around - window, end=around + window, limit=200)
        )


class SentinelLogSource(LogSource):
    """
    Placeholder only. See docs/SENTINEL_INTEGRATION.md for how this would
    be implemented against Microsoft Sentinel / Log Analytics. This class
    intentionally returns no fake data.
    """

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "SentinelLogSource is not implemented in this project. See "
            "docs/SENTINEL_INTEGRATION.md for the intended integration "
            "design (Azure AD auth, KQL execution via azure-monitor-query, "
            "incident retrieval)."
        )

    def search_logs(self, query: LogQuery) -> list[dict]:  # pragma: no cover
        raise NotImplementedError

    def get_user_activity(self, user, window, around):  # pragma: no cover
        raise NotImplementedError

    def get_host_activity(self, hostname, window, around):  # pragma: no cover
        raise NotImplementedError


def get_log_source(db: Session) -> LogSource:
    from app.config.settings import settings

    if settings.log_source == "sentinel":
        return SentinelLogSource()
    return LocalLogSource(db)
