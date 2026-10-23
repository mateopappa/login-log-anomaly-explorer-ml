"""Threat Lab API lists catalog scenarios without requiring paid services."""

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
        database_url=f"sqlite+pysqlite:///{tmp_path / 'threat.db'}",
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


def test_list_threat_scenarios(client: TestClient) -> None:
    response = client.get("/api/v1/threat-lab/scenarios")
    assert response.status_code == 200
    rows = response.json()
    assert rows
    assert "scenario_id" in rows[0]
    assert "strategy" in rows[0]
