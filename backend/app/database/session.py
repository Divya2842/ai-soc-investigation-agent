from __future__ import annotations
from collections.abc import Generator
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from app.config.settings import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_session_factory():
    """
    FastAPI dependency returning the session *factory* itself (not a
    session instance) -- for code paths like BackgroundTasks that need to
    open their own session after the request's session may already be
    closed. Exists as its own overridable dependency (distinct from
    `get_db`) purely so tests can point background tasks at the same
    in-memory test database the request itself used; see tests/conftest.py.
    """
    return SessionLocal


def init_db() -> None:
    """Create all tables. Safe to call repeatedly (no-op if they exist)."""
    # Import models so they register on Base.metadata before create_all.
    from app.models import (  # noqa: F401
        alert,
        investigation,
        ioc,
        ioc_enrichment,
        log_event,
        response_action,
        user,
    )
    from app.services import audit  # noqa: F401 -- registers AuditLogEntry

    Base.metadata.create_all(bind=engine)
    _run_lightweight_migrations()


def _run_lightweight_migrations() -> None:
    """
    This project has no Alembic (deliberately -- a single-file SQLite
    database for a project this size doesn't need a migration framework).
    `Base.metadata.create_all()` above only creates *missing tables*; it
    will not add new columns to a table that already exists from a prior
    version of a model. This function closes that gap for existing
    deployments (e.g. someone's local `soc.db` predating the enrichment
    status/count columns or the investigation disposition/report columns)
    by adding any columns present on the current models but missing from
    the actual database, using `ALTER TABLE ... ADD COLUMN`, which SQLite
    supports without rewriting or losing existing rows.

    New columns must be nullable or have a server-independent default that
    SQLite can apply to existing rows; all columns added this way in this
    project satisfy that.
    """
    if not settings.database_url.startswith("sqlite"):
        # Non-SQLite deployments should use a real migration tool (Alembic)
        # instead of this helper -- intentionally a no-op here.
        return

    inspector = inspect(engine)
    migrations: dict[str, list[tuple[str, str]]] = {
    "ioc_enrichments": [
        ("status", "VARCHAR(16) DEFAULT 'completed'"),
        ("malicious_count", "INTEGER"),
        ("suspicious_count", "INTEGER"),
        ("harmless_count", "INTEGER"),
        ("created_year", "INTEGER"),
        ("owner", "VARCHAR(256)"),
        ("digitally_signed_by", "VARCHAR(256)"),
    ],
    "investigations": [
        ("status", "VARCHAR(16) DEFAULT 'completed'"),
        ("disposition", "VARCHAR(16) DEFAULT 'inconclusive'"),
        ("requires_customer_validation", "BOOLEAN DEFAULT 0"),
        ("report_markdown", "TEXT DEFAULT ''"),
    ],
    }

    with engine.begin() as conn:
        for table_name, columns in migrations.items():
            if table_name not in inspector.get_table_names():
                continue  # table doesn't exist yet; create_all() will have made it with all columns
            existing_columns = {col["name"] for col in inspector.get_columns(table_name)}
            for column_name, ddl_type in columns:
                if column_name not in existing_columns:
                    conn.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl_type}")
                    )