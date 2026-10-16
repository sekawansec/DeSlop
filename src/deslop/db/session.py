"""Engine / session management and schema bootstrap."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config.settings import Settings, get_settings
from .base import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def make_engine(settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    kwargs: dict = {"pool_pre_ping": True, "future": True}
    if settings.is_sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(settings.database_url, **kwargs)


def get_engine(settings: Settings | None = None) -> Engine:
    global _engine
    if _engine is None:
        _engine = make_engine(settings)
    return _engine


def get_sessionmaker(settings: Settings | None = None) -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(settings), expire_on_commit=False)
    return _SessionLocal


@contextmanager
def session_scope(settings: Settings | None = None) -> Iterator[Session]:
    """Transactional session context manager."""
    factory = get_sessionmaker(settings)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine() -> None:
    """Dispose and clear cached engine/sessionmaker (used by tests)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


#: Columns added after the initial schema. ``init_db`` backfills them with
#: ``ALTER TABLE`` when they are missing so existing deployments keep working
#: without a separate migration runner.
_LATE_COLUMNS: dict[str, dict[str, str]] = {
    "reports": {
        "attestation": "BOOLEAN DEFAULT FALSE",
        "ai_used": "VARCHAR(16)",
        "poc_url": "VARCHAR(500)",
        "production_approved": "BOOLEAN DEFAULT FALSE",
    },
    "repro_plans": {
        "bug_class": "VARCHAR(64)",
    },
    "triage_results": {
        "production_gate": "BOOLEAN DEFAULT FALSE",
    },
}


def _ensure_columns(engine: Engine) -> None:
    from sqlalchemy import inspect

    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, cols in _LATE_COLUMNS.items():
            if table not in inspector.get_table_names():
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in cols.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def init_db(settings: Settings | None = None) -> None:
    """Create the pgvector extension (Postgres) and all tables."""
    settings = settings or get_settings()
    engine = get_engine(settings)
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(engine)
    _ensure_columns(engine)
