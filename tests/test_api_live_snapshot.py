"""Live API returns an actionable snapshot, not only a flat summary dump."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from login_anomaly.api.app import create_app
from login_anomaly.config import Settings
from login_anomaly.persistence.db import reset_engine
from login_anomaly.services.app_state import reset_state


@pytest.fixture()
def client(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'live.db'}",
        cors_origins=("http://localhost:5173",),
        investigator_default="mock",
        anthropic_api_key=None,
        anthropic_model="claude-haiku-5-5",
    )
    reset_engine()
    reset_state()
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client
    reset_engine()
    reset_state()


def test_idle_snapshot_and_replay_advance(client: TestClient) -> None:
    idle = client.get("/api/v1/live/status")
    assert idle.status_code == 200
    body = idle.json()
    assert body["active"] is False
    assert body["state"] == "idle"
    assert "scenarios" in body
    assert body["recent_events"] == []

    explainer = client.get("/api/v1/soc/data-explainer")
    assert explainer.status_code == 200
    assert "campaign_types" in explainer.json()

    started = client.post(
        "/api/v1/live/control",
        json={"action": "start", "mode": "replay", "seed": 7, "scenario": "Mixed campaigns", "events_per_second": 20},
    )
    assert started.status_code == 200, started.text
    assert started.json()["active"] is True
    assert started.json()["state"] == "running"

    # Release is clock-based: wait briefly so events_per_second accrues.
    time.sleep(0.25)
    advanced = client.post("/api/v1/live/control", json={"action": "advance"})
    assert advanced.status_code == 200
    snap = advanced.json()
    assert snap["summary"]["released"] >= 1
    assert isinstance(snap["recent_events"], list)
    assert len(snap["recent_events"]) >= 1
    assert isinstance(snap["cases"], list)
    assert isinstance(snap["alerts"], list)
