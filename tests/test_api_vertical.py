"""API vertical: health, seed, cases, mock investigation, idempotency."""

from __future__ import annotations

import os
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
    db_path = tmp_path / "test.db"
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{db_path}",
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


def test_health_and_ready(client: TestClient) -> None:
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    ready = client.get("/api/v1/ready")
    assert ready.status_code == 200
    body = ready.json()
    assert body["database"] == "ok"
    assert body["investigator"]["mock_available"] is True
    assert body["investigator"]["haiku_configured"] is False


def test_seed_list_case_and_reinvestigate(client: TestClient) -> None:
    seed = client.post("/api/v1/soc/seed", json={"seed": 11})
    assert seed.status_code == 200, seed.text
    payload = seed.json()
    assert payload["cases"] > 0
    assert payload["events"] > 0

    cases = client.get("/api/v1/cases")
    assert cases.status_code == 200
    rows = cases.json()
    assert rows
    case_id = rows[0]["case_id"]

    detail = client.get(f"/api/v1/cases/{case_id}")
    assert detail.status_code == 200
    dossier = detail.json()
    assert dossier["case_id"] == case_id
    assert dossier["events"]
    assert dossier["investigations"]

    first = client.post(
        f"/api/v1/cases/{case_id}/investigations",
        json={"provider": "mock", "idempotency_key": "retry-1"},
    )
    assert first.status_code == 200, first.text
    run = first.json()
    assert run["mode"] == "mock"
    assert run["status"] == "completed"
    assert run["result"]["verdict"] in {"malicious", "benign", "inconclusive"}
    assert run["review"]["mode"] == "deterministic"

    second = client.post(
        f"/api/v1/cases/{case_id}/investigations",
        json={"provider": "mock", "idempotency_key": "retry-1"},
    )
    assert second.status_code == 200
    assert second.json()["run_id"] == run["run_id"]

    fetched = client.get(f"/api/v1/investigations/{run['run_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["run_id"] == run["run_id"]


def test_haiku_without_key_returns_503(client: TestClient) -> None:
    seed = client.post("/api/v1/soc/seed", json={"seed": 12})
    assert seed.status_code == 200
    case_id = client.get("/api/v1/cases").json()[0]["case_id"]
    response = client.post(f"/api/v1/cases/{case_id}/investigations", json={"provider": "haiku"})
    assert response.status_code == 503


def test_soc_summary(client: TestClient) -> None:
    client.post("/api/v1/soc/seed", json={"seed": 13})
    summary = client.get("/api/v1/soc/summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["cases_total"] > 0
    assert body["investigator"]["mock_available"] is True
