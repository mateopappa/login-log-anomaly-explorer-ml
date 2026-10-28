"""Pipeline architecture + multi-site catalog for the product UI."""

from __future__ import annotations

import os
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from fastapi import APIRouter

from login_anomaly.tenants import list_tenants

router = APIRouter(tags=["pipeline"])


@router.get("/pipeline/status")
def pipeline_status() -> dict[str, Any]:
    """Describe the event-driven path and optionally probe worker /metrics."""
    grafana_url = os.environ.get("GRAFANA_URL", "http://localhost:3000")
    prometheus_url = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
    worker_metrics_url = os.environ.get("WORKER_METRICS_URL", "http://localhost:9100/metrics")
    redpanda_console = os.environ.get("REDPANDA_CONSOLE_URL", "http://localhost:8081")
    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")

    worker_reachable = _probe(worker_metrics_url.replace("/metrics", "/healthz"))
    return {
        "title": "Multi-site event pipeline",
        "summary": (
            "Five synthetic tenants publish AuthEvents to Redpanda. "
            "A worker consumes each site topic, runs rules and the ML baseline, and writes cases "
            "into the same SOC queue. Prometheus still receives the rule metrics. "
            "Compose runs the broker path locally; managed Kafka + consumer HPA is a natural production mapping, not in-repo."
        ),
        "scope": {
            "persists_cases": True,
            "runs_ml": True,
            "runs_rules": True,
            "exports_metrics": True,
            "product_case_path": "five sites / seed / SOC Live → Postgres",
        },
        "broker": {
            "kind": "redpanda",
            "kafka_api": kafka_bootstrap,
            "console_url": redpanda_console,
            "protocol": "Kafka-compatible (no Kafka JVM required)",
        },
        "observability": {
            "prometheus_url": prometheus_url,
            "grafana_url": grafana_url,
            "worker_metrics_url": worker_metrics_url,
            "worker_reachable": worker_reachable,
        },
        "tenants": list_tenants(),
        "topics": [row["topic"] for row in list_tenants()],
        "compose_profile": "pipeline",
        "how_to_run": [
            "docker compose --profile pipeline up --build",
            "Open Pipeline page in the SOC console for tenant catalog + links",
            "Open Grafana (admin/admin) → Login Anomaly dashboard",
            "Open Redpanda Console to inspect topics and messages",
        ],
        "k8s_narrative": (
            "A production mapping would place site producers near each subsidiary, "
            "a managed Kafka/Redpanda cluster as the bus, and a consumer group with HPA. "
            "This repo does not ship Kubernetes manifests — Compose is the executable proof."
        ),
    }


def _probe(url: str) -> bool:
    try:
        with urlopen(url, timeout=0.4) as response:  # noqa: S310 — local health probe
            return 200 <= response.status < 300
    except (URLError, TimeoutError, OSError):
        return False
