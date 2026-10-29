"""Cases list defaults to latest dataset; scope=all returns history."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from login_anomaly.api.app import create_app
from login_anomaly.config import Settings
from login_anomaly.persistence import repositories as repo
from login_anomaly.persistence.db import reset_engine, session_scope
from login_anomaly.persistence.models import CaseRow
from login_anomaly.services.app_state import reset_state


@pytest.fixture()
def client(tmp_path: Path):
    db_path = tmp_path / "scope.db"
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


def test_seed_batch_size_and_latest_scope(client: TestClient) -> None:
    first = client.post("/api/v1/soc/seed", json={"seed": 11})
    assert first.status_code == 200
    body = first.json()
    assert 1500 <= body["events"] <= 2000
    assert body["cases"] > 0
    dataset_a = body["dataset_id"]

    latest = client.get("/api/v1/cases", params={"scope": "latest"})
    assert latest.status_code == 200
    assert all(row["dataset_id"] == dataset_a for row in latest.json())

    second = client.post("/api/v1/soc/seed", json={"seed": 12})
    assert second.status_code == 200
    dataset_b = second.json()["dataset_id"]
    assert dataset_b != dataset_a

    only_latest = client.get("/api/v1/cases", params={"scope": "latest"})
    assert only_latest.status_code == 200
    assert len(only_latest.json()) > 0
    assert all(row["dataset_id"] == dataset_b for row in only_latest.json())

    all_cases = client.get("/api/v1/cases", params={"scope": "all"})
    assert all_cases.status_code == 200
    ids = {row["dataset_id"] for row in all_cases.json()}
    assert dataset_a in ids and dataset_b in ids

    summary = client.get("/api/v1/soc/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["active_dataset_id"] == dataset_b
    assert payload["active_seed"] == 12
    assert payload["events_total"] == second.json()["events"]
    assert payload["scope"] == "latest"
    assert isinstance(payload["cases_by_kind"], dict)
    assert sum(payload["cases_by_kind"].values()) == payload["cases_total"]

    started = client.post(
        "/api/v1/live/control",
        json={"action": "start", "mode": "replay", "seed": 12, "scenario": "Benign only", "events_per_second": 5},
    )
    assert started.status_code == 200, started.text
    still_batch = client.get("/api/v1/cases", params={"scope": "latest"})
    assert all(row["dataset_id"] == dataset_b for row in still_batch.json())
    after = client.get("/api/v1/soc/summary").json()
    assert after["active_dataset_id"] == dataset_b
    assert str(after["live_dataset_id"]).startswith("sim-")
    live_cases = client.get("/api/v1/cases", params={"scope": "live"})
    assert live_cases.status_code == 200
    assert all(row["dataset_id"].startswith("sim-") for row in live_cases.json())


def test_sites_scope_is_latest_publish_and_live_scope_is_open(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    url = client.app.state.settings.database_url
    with session_scope(url) as session:
        older = repo.upsert_dataset(
            session,
            "site-old",
            1,
            {"source": "site", "tenant_id": "acme-hq", "display_name": "Acme Corp · HQ"},
        )
        older.created_at = now - timedelta(hours=2)
        repo.upsert_dataset(
            session,
            "site-new",
            2,
            {"source": "site", "tenant_id": "acme-hq", "display_name": "Acme Corp · HQ"},
        )
        repo.upsert_dataset(session, "sim-queue", 3, {"source": "soc_live", "mode": "replay"})
        for case_id, dataset_id, status in (
            ("case-old", "site-old", "open"),
            ("case-new", "site-new", "open"),
            ("case-open", "sim-queue", "open"),
            ("case-closed", "sim-queue", "closed"),
        ):
            session.add(
                CaseRow(
                    id=case_id,
                    dataset_id=dataset_id,
                    case_kind="rule_backed",
                    priority_hint="rule_high",
                    status=status,
                    event_ids_json=["evt-1"],
                    signals_json=[],
                    associations_json=[],
                    created_at=now,
                    updated_at=now,
                )
            )

    sites = client.get("/api/v1/cases", params={"scope": "sites"})
    assert sites.status_code == 200
    assert {row["case_id"] for row in sites.json()} == {"case-new"}
    assert sites.json()[0]["site"] == "Acme Corp · HQ"

    live = client.get("/api/v1/cases", params={"scope": "live"})
    assert live.status_code == 200
    assert live.json() == []

    started = client.post(
        "/api/v1/live/control",
        json={"action": "start", "mode": "replay", "seed": 42, "scenario": "Mixed campaigns", "events_per_second": 8},
    )
    assert started.status_code == 200, started.text
    sim_id = started.json()["summary"]["simulation_id"]
    assert sim_id != "sim-queue"
    with session_scope(url) as session:
        repo.upsert_dataset(session, sim_id, 42, {"source": "soc_live", "mode": "replay"})
        session.add(
            CaseRow(
                id="case-this-sim",
                dataset_id=sim_id,
                case_kind="ml_only",
                priority_hint="ml_untriaged",
                status="open",
                event_ids_json=["evt-1"],
                signals_json=[],
                associations_json=[],
                created_at=now,
                updated_at=now,
            )
        )

    running = client.get("/api/v1/cases", params={"scope": "live"})
    assert running.status_code == 200
    assert {row["case_id"] for row in running.json()} == {"case-this-sim"}

    reset = client.post("/api/v1/live/control", json={"action": "reset"})
    assert reset.status_code == 200, reset.text
    cleared = client.get("/api/v1/cases", params={"scope": "live"})
    assert cleared.json() == []
    assert client.get("/api/v1/cases/case-this-sim").status_code == 404
    sites_after = client.get("/api/v1/cases", params={"scope": "sites"})
    assert {row["case_id"] for row in sites_after.json()} == {"case-new"}


def test_dataset_id_lists_a_saved_replay_without_a_live_sim(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    url = client.app.state.settings.database_url
    with session_scope(url) as session:
        repo.upsert_dataset(session, "sim-saved", 42, {"source": "soc_live", "scenario": "Boundary lab"})
        repo.upsert_dataset(session, "sim-other", 7, {"source": "soc_live", "scenario": "Mixed campaigns"})
        for case_id, dataset_id, status in (
            ("case-open-saved", "sim-saved", "open"),
            ("case-closed-saved", "sim-saved", "closed"),
            ("case-other", "sim-other", "open"),
        ):
            session.add(
                CaseRow(
                    id=case_id,
                    dataset_id=dataset_id,
                    case_kind="ml_only",
                    priority_hint="ml_untriaged",
                    status=status,
                    event_ids_json=["evt-1"],
                    signals_json=[],
                    associations_json=[],
                    created_at=now,
                    updated_at=now,
                )
            )

    listed = client.get("/api/v1/cases", params={"dataset_id": "sim-saved", "limit": 1000})
    assert listed.status_code == 200
    assert {row["case_id"] for row in listed.json()} == {"case-open-saved", "case-closed-saved"}
    assert client.get("/api/v1/cases", params={"scope": "live"}).json() == []
