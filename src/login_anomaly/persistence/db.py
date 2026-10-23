"""Engine and session helpers. Supports Postgres (product) and SQLite (local/tests)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from login_anomaly.persistence.models import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine(database_url: str) -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        connect_args: dict[str, object] = {}
        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _engine = create_engine(database_url, future=True, connect_args=connect_args)
        if database_url.startswith("sqlite"):

            @event.listens_for(_engine, "connect")
            def _sqlite_fk(dbapi_connection, connection_record) -> None:  # type: ignore[no-untyped-def]
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)
    return _engine


def get_session_factory(database_url: str) -> sessionmaker[Session]:
    get_engine(database_url)
    assert _SessionLocal is not None
    return _SessionLocal


def init_db(database_url: str) -> None:
    """Create tables. Alembic is preferred in Docker; this covers local SQLite demos/tests."""
    engine = get_engine(database_url)
    Base.metadata.create_all(bind=engine)


def reset_engine() -> None:
    """Test helper: drop the process-wide engine so a new URL can be used."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope(database_url: str) -> Iterator[Session]:
    factory = get_session_factory(database_url)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
