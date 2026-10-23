"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from login_anomaly.api.routers import (
    cases,
    evaluations,
    health,
    investigations,
    live,
    pipeline,
    product,
    soc,
    threat_lab,
)
from login_anomaly.config import Settings, load_settings
from login_anomaly.persistence.db import init_db
from login_anomaly.services.app_state import get_state, reset_state


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or load_settings()
    reset_state()
    state = get_state()
    state.settings = cfg
    init_db(cfg.database_url)

    app = FastAPI(
        title="Login Log Anomaly Explorer",
        version="0.1.0",
        description="SOC investigation API over the existing detection and agentic engine.",
    )
    app.state.settings = cfg
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cfg.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(soc.router, prefix="/api/v1")
    app.include_router(cases.router, prefix="/api/v1")
    app.include_router(investigations.router, prefix="/api/v1")
    app.include_router(live.router, prefix="/api/v1")
    app.include_router(evaluations.router, prefix="/api/v1")
    app.include_router(threat_lab.router, prefix="/api/v1")
    app.include_router(product.router, prefix="/api/v1")
    app.include_router(pipeline.router, prefix="/api/v1")
    return app


def app() -> FastAPI:
    """Uvicorn entry: ``uvicorn login_anomaly.api.app:app --factory``."""
    return create_app()
