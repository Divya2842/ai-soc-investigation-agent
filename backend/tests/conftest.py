from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure `app` package is importable when running pytest from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.database.session import Base, get_db, get_session_factory  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine)

    from app.models import (  # noqa: F401
        alert,
        investigation,
        ioc,
        ioc_enrichment,
        log_event,
        response_action,
    )
    from app.services import audit  # noqa: F401

    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()
    session.test_session_factory = TestingSessionLocal  # stashed for the client fixture below
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    from fastapi.testclient import TestClient

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    def _override_get_session_factory():
        # Background tasks (e.g. automatic IOC enrichment) open their own
        # session via this factory -- point it at the same in-memory
        # engine (StaticPool keeps one shared connection) the request used,
        # instead of the real app.database.session.SessionLocal.
        return db_session.test_session_factory

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_session_factory] = _override_get_session_factory
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
