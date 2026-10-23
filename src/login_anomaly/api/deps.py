"""FastAPI dependencies."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from login_anomaly.config import Settings
from login_anomaly.persistence.db import get_session_factory
from login_anomaly.services.app_state import AppState, get_state


def settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def app_state_dep() -> AppState:
    return get_state()


def db_session(request: Request) -> Iterator[Session]:
    factory = get_session_factory(request.app.state.settings.database_url)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
