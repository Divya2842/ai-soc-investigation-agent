from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class LogEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    log_type: str
    timestamp: datetime
    hostname: str | None = None
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    payload: dict[str, Any]
