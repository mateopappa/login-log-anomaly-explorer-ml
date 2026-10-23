from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

from login_anomaly.api.schemas import HealthResponse, ReadyResponse
from login_anomaly.config import Settings
from login_anomaly.api.deps import settings_dep
from login_anomaly.persistence.db import get_engine
from login_anomaly.services.providers import provider_status

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", version="0.1.0")


@router.get("/ready", response_model=ReadyResponse)
def ready(request: Request, settings: Settings = Depends(settings_dep)) -> ReadyResponse:
    db_status = "ok"
    try:
        engine = get_engine(settings.database_url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"
    return ReadyResponse(
        status="ok" if db_status == "ok" else "degraded",
        database=db_status,
        investigator=provider_status(settings),
    )
