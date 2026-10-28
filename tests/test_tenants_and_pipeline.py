"""Multi-site catalog, envelopes, and product/pipeline API contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from login_anomaly.pipeline.envelope import StreamEnvelope
from login_anomaly.pipeline.synthesize import build_tenant_envelopes
from login_anomaly.tenants import TENANTS, get_tenant, list_tenants

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from login_anomaly.api.app import create_app
from login_anomaly.config import Settings
from login_anomaly.persistence.db import reset_engine
from login_anomaly.services.app_state import reset_state


@pytest.fixture()
def client(tmp_path: Path):
    db_path = tmp_path / "pipeline.db"
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


def test_five_tenants_with_unique_topics() -> None:
    assert len(TENANTS) == 5
    topics = {tenant.topic for tenant in TENANTS}
    assert len(topics) == 5
    assert get_tenant("acme-hq").region == "US"
    rows = list_tenants()
    assert rows[0]["tenant_id"] == "acme-hq"


def test_namespaced_envelopes_are_valid() -> None:
    tenant = get_tenant("contoso-jp")
    envelopes = build_tenant_envelopes(tenant, base_seed=7, n_events=120, n_accounts=30)
    assert len(envelopes) == 120
    first = envelopes[0]
    assert first.tenant_id == "contoso-jp"
    assert first.event.event_id.startswith("contoso-jp-")
    assert first.event.account_id.startswith("contoso-jp-")
    roundtrip = StreamEnvelope.from_dict(first.to_dict())
    assert roundtrip.event.event_id == first.event.event_id
    # Namespace is idempotent on already-prefixed ids only if we pass raw events;
    # here we check raw generate path stays under identifier length.
    assert len(first.event.event_id) <= 64
    assert len(first.event.account_id) <= 64


def test_product_and_pipeline_endpoints(client: TestClient) -> None:
    demo = client.get("/api/v1/product/demo-path")
    assert demo.status_code == 200
    body = demo.json()
    assert len(body["steps"]) >= 5
    assert body["steps"][0]["title"] == "Seed"
    assert "seed=42" in body["steps"][0]["route"]
    assert body.get("presenter_route") == "/story"
    assert "prove" not in body["pitch"].lower()
    assert any(step["id"] == "score" for step in body["steps"])

    story = client.get("/api/v1/product/story")
    assert story.status_code == 200
    beats = story.json()["beats"]
    assert len(beats) >= 8
    assert beats[0]["id"] == "hook"
    assert beats[-1]["id"] == "close"
    assert all(beat["id"] != "prove" for beat in beats)
    assert all(isinstance(beat.get("say"), str) and len(beat["say"]) > 20 for beat in beats)
    assert "prove" not in " ".join(beat.get("say", "") for beat in beats).lower()

    trust = client.get("/api/v1/product/trust")
    assert trust.status_code == 200
    assert len(trust.json()["bullets"]) >= 4
    assert all(len(item["text"]) < 80 for item in trust.json()["bullets"])

    tenants = client.get("/api/v1/product/tenants")
    assert tenants.status_code == 200
    assert len(tenants.json()) == 5

    pipeline = client.get("/api/v1/pipeline/status")
    assert pipeline.status_code == 200
    status = pipeline.json()
    assert status["broker"]["kind"] == "redpanda"
    assert len(status["topics"]) == 5
    assert "docker compose" in status["how_to_run"][0]
    assert status["scope"]["persists_cases"] is True
    assert status["scope"]["runs_ml"] is True
    assert status["scope"]["runs_rules"] is True
    assert "kubernetes" not in status["summary"].lower()
    assert "manifests" in status["k8s_narrative"].lower()
