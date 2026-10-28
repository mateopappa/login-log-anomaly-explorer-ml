"""Per-case offline evaluation against rebuilt ground truth."""

from __future__ import annotations

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
        database_url=f"sqlite+pysqlite:///{tmp_path / 'case-eval.db'}",
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


def test_evaluate_case_after_investigation(client: TestClient) -> None:
    seeded = client.post("/api/v1/soc/seed", json={"seed": 19})
    assert seeded.status_code == 200, seeded.text
    cases = client.get("/api/v1/cases").json()
    assert cases
    case_id = cases[0]["case_id"]

    too_early = client.post(f"/api/v1/cases/{case_id}/evaluate")
    # Seed already persists mock investigations — evaluation should work immediately.
    assert too_early.status_code in {200, 409}

    if too_early.status_code == 409:
        investigated = client.post(
            f"/api/v1/cases/{case_id}/investigations",
            json={"provider": "mock", "idempotency_key": "eval-once"},
        )
        assert investigated.status_code == 200, investigated.text
        scored = client.post(f"/api/v1/cases/{case_id}/evaluate")
    else:
        scored = too_early

    assert scored.status_code == 200, scored.text
    body = scored.json()
    assert body["case_id"] == case_id
    metrics = body["metrics"]
    assert metrics["verdict_match"] in {"correct", "incorrect", "inconclusive"}
    assert metrics["expected_verdict"] in {"malicious", "benign"}
    assert "policy" in metrics
    assert metrics["event_count"] >= 1


def test_evaluate_refuses_when_case_events_change(client: TestClient) -> None:
    seeded = client.post("/api/v1/soc/seed", json={"seed": 21})
    assert seeded.status_code == 200, seeded.text
    case_id = client.get("/api/v1/cases").json()[0]["case_id"]
    scored = client.post(f"/api/v1/cases/{case_id}/evaluate")
    assert scored.status_code == 200, scored.text

    from login_anomaly.persistence.db import session_scope
    from login_anomaly.persistence.models import CaseRow

    url = client.app.state.settings.database_url
    with session_scope(url) as session:
        row = session.get(CaseRow, case_id)
        assert row is not None
        row.event_ids_json = [*row.event_ids_json, "extra-event-id"]

    again = client.post(f"/api/v1/cases/{case_id}/evaluate")
    assert again.status_code == 409
    assert again.json()["detail"] == "case evidence changed since this run; investigate again"
