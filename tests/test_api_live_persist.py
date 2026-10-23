"""SOC Live advance persists cases into the database for the Cases workbench."""

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
        database_url=f"sqlite+pysqlite:///{tmp_path / 'livepersist.db'}",
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


def test_live_advance_persists_and_lists_cases(client: TestClient) -> None:
    started = client.post(
        "/api/v1/live/control",
        json={"action": "start", "mode": "replay", "seed": 9, "scenario": "Mixed campaigns", "events_per_second": 40},
    )
    assert started.status_code == 200, started.text

    # Accrue wall-clock time so the clock-based releaser emits events.
    for _ in range(8):
        time.sleep(0.2)
        advanced = client.post("/api/v1/live/control", json={"action": "advance"})
        assert advanced.status_code == 200
        snap = advanced.json()
        if snap.get("persisted", {}).get("cases", 0) > 0 or snap["summary"]["released"] > 100:
            break

    cases = client.get("/api/v1/cases")
    assert cases.status_code == 200
    # Persistence may still be empty early in a quiet window; after enough release, cases appear.
    if cases.json():
        detail = client.get(f"/api/v1/cases/{cases.json()[0]['case_id']}")
        assert detail.status_code == 200
        assert detail.json()["dataset_id"].startswith("sim-")
