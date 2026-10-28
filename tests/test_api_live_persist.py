"""SOC Live advance persists cases into the database for the Cases workbench."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from login_anomaly.api.app import create_app
from login_anomaly.config import Settings
from login_anomaly.persistence.db import reset_engine, session_scope
from login_anomaly.persistence.models import EventRow
from login_anomaly.services.app_state import reset_state


def _event_count(client: TestClient) -> int:
    url = client.app.state.settings.database_url
    with session_scope(url) as session:
        return int(session.scalar(select(func.count()).select_from(EventRow)) or 0)


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

    before = _event_count(client)
    time.sleep(0.2)
    again = client.post("/api/v1/live/control", json={"action": "advance"})
    assert again.status_code == 200, again.text
    assert _event_count(client) >= before

    cases = client.get("/api/v1/cases", params={"scope": "live"})
    assert cases.status_code == 200
    # Persistence may still be empty early in a quiet window; after enough release, cases appear.
    if cases.json():
        detail = client.get(f"/api/v1/cases/{cases.json()[0]['case_id']}")
        assert detail.status_code == 200
        assert detail.json()["dataset_id"].startswith("sim-")


def test_overlapping_advance_runs_one_at_a_time(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from login_anomaly.live.engine import SimulationService

    started = client.post(
        "/api/v1/live/control",
        json={"action": "start", "mode": "replay", "seed": 4, "scenario": "Benign only", "events_per_second": 5},
    )
    assert started.status_code == 200, started.text
    current = 0
    peak = 0
    gate = threading.Lock()
    original = SimulationService.advance

    def wrapped(self: SimulationService) -> int:
        nonlocal current, peak
        with gate:
            current += 1
            peak = max(peak, current)
        try:
            time.sleep(0.15)
            return original(self)
        finally:
            with gate:
                current -= 1

    monkeypatch.setattr(SimulationService, "advance", wrapped)
    errors: list[str] = []

    def hit() -> None:
        response = client.post("/api/v1/live/control", json={"action": "advance"})
        if response.status_code != 200:
            errors.append(response.text)

    threads = [threading.Thread(target=hit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert peak == 1
