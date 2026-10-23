"""Product storytelling contracts: demo path, trust model, multi-site catalog."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from login_anomaly.tenants import list_tenants

router = APIRouter(tags=["product"])


@router.get("/product/demo-path")
def demo_path() -> dict[str, Any]:
    return {
        "title": "Demo path — Login Log Anomaly Explorer",
        "pitch": (
            "Synthetic multi-site authentication telemetry → independent detectors → "
            "cases → bounded investigator agent → deterministic review → offline evaluation."
        ),
        "audience": "Proofpoint bootcamp / security engineering interview demo",
        "steps": [
            {
                "id": "lab",
                "title": "1. Build the haystack",
                "route": "/",
                "action": "Seed demo dataset (pick a seed)",
                "why": "Reproducible synthetic world. Same seed → same events. Ground truth exists only for later evaluation.",
            },
            {
                "id": "streams",
                "title": "2. Watch multi-site streams",
                "route": "/pipeline",
                "action": "Open Pipeline & Observability",
                "why": "Five tenants publish AuthEvents through a Kafka-compatible broker (Redpanda). A worker consumes, detects, and persists.",
            },
            {
                "id": "live",
                "title": "3. SOC Live triage",
                "route": "/detection",
                "action": "Start replay with auto-advance",
                "why": "Operational console: release → detect → case → investigate in simulated time.",
            },
            {
                "id": "investigate",
                "title": "4. Investigate with an agent",
                "route": "/cases",
                "action": "Open a case → Investigate (mock), then Haiku if configured",
                "why": "Read-only tools, budgets, structured verdict. Python enforces policy; the model cannot remediate or read labels.",
            },
            {
                "id": "evaluate",
                "title": "5. Prove it with metrics",
                "route": "/evaluation",
                "action": "Run benchmark mock (and Haiku if key present)",
                "why": "Precision/recall/F1 for detectors; investigation quality offline. No unverified claims.",
            },
        ],
        "talking_points": [
            "Rules and ML stay independent — no hybrid score aggregation.",
            "Investigator is an agent loop with allowlisted tools, not a free-form chatbot.",
            "Mock baseline is labeled honestly; Claude Haiku is optional and explicit.",
            "Ground truth never enters runtime detectors or investigation tools.",
            "Event-driven path uses a real broker in Docker; Kubernetes is the production narrative, not a required demo dependency.",
        ],
    }


@router.get("/product/trust")
def trust_model() -> dict[str, Any]:
    return {
        "title": "Trust & evaluation model",
        "bullets": [
            {
                "title": "Synthetic by design",
                "text": "All login traffic is generated. IPs are documentation/private ranges so data cannot be mistaken for production.",
            },
            {
                "title": "Ground-truth isolation",
                "text": "Labels live only in simulation/evaluation packages. AST tests block runtime imports of ground truth.",
            },
            {
                "title": "Agent containment",
                "text": "Tools are read-only and allowlisted. Forbidden tools (remediation, get_ground_truth) are policy violations.",
            },
            {
                "title": "Independent detectors",
                "text": "Rules and ML produce separate signals; correlation uses exact event ids only.",
            },
            {
                "title": "Honest baselines",
                "text": "Mock investigator is deterministic and labeled. LLM runs show model id, tokens, and estimated cost when available.",
            },
        ],
    }


@router.get("/product/tenants")
def tenants() -> list[dict[str, Any]]:
    return list_tenants()
