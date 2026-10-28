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
    event = snap["recent_events"][0]
    assert {"event_id", "source_ip", "country_code", "outcome", "account_id"} <= set(event)
    assert isinstance(snap["cases"], list)
    assert isinstance(snap["alerts"], list)

    # Keep advancing until a rule alert appears so the session-flow UI can join event_ids.
    for _ in range(40):
        time.sleep(0.15)
        snap = client.post("/api/v1/live/control", json={"action": "advance"}).json()
        if snap["alerts"]:
            break
    if snap["alerts"]:
        assert "event_ids" in snap["alerts"][0]
        assert isinstance(snap["alerts"][0]["event_ids"], list)

    scored = client.post("/api/v1/live/score")
    assert scored.status_code == 200, scored.text
    metrics = scored.json()["metrics"]
    assert metrics["partial"] is True
    assert metrics["rules"]["enabled"] is True
    assert metrics["ml"]["enabled"] is True
    assert metrics["case_quality"]["awaiting"] >= 0
    assert "Ground truth was rebuilt offline" in metrics["note"]

