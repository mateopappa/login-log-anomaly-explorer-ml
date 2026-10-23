"""Product storytelling contracts: demo path, trust model, multi-site catalog, presenter beats."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from login_anomaly.tenants import list_tenants

router = APIRouter(tags=["product"])


@router.get("/product/demo-path")
def demo_path() -> dict[str, Any]:
    return {
        "title": "Demo path",
        "pitch": "Synthetic logins → detect → case → investigate → prove.",
        "audience": "Proofpoint bootcamp / security engineering demo",
        "presenter_route": "/story",
        "steps": [
            {
                "id": "lab",
                "title": "Seed",
                "route": "/?seed=42&autoseed=1",
                "action": "Seed world",
                "why": "Same seed → same events.",
            },
            {
                "id": "streams",
                "title": "Streams",
                "route": "/pipeline",
                "action": "5 sites live",
                "why": "Broker + worker.",
            },
            {
                "id": "live",
                "title": "Triage",
                "route": "/detection?seed=42&autostart=1&rate=8",
                "action": "SOC Live",
                "why": "Release → detect → case.",
            },
            {
                "id": "investigate",
                "title": "Investigate",
                "route": "/cases",
                "action": "Open a case",
                "why": "Bounded agent tools.",
            },
            {
                "id": "evaluate",
                "title": "Prove",
                "route": "/evaluation",
                "action": "Run metrics",
                "why": "Precision / recall / F1.",
            },
            {
                "id": "adversarial",
                "title": "Stress",
                "route": "/threat-lab",
                "action": "One scenario",
                "why": "Offline adversarial eval.",
            },
        ],
        "talking_points": [
            "Rules ⊥ ML — no hybrid score.",
            "Agent = allowlisted tools, not a chatbot.",
            "Mock labeled; Haiku optional.",
            "Ground truth never in runtime.",
            "Compose proves the broker; K8s is the prod story.",
        ],
    }


@router.get("/product/story")
def story_beats() -> dict[str, Any]:
    """TED-style presenter beats for /story — keyboard-driven, one idea per screen."""
    return {
        "title": "Login Anomaly Explorer",
        "subtitle": "From synthetic logins to audited verdicts",
        "controls": "← → or space · Esc exits",
        "beats": [
            {
                "id": "hook",
                "kicker": "The problem",
                "headline": "Suspicious logins drown in noise.",
                "line": "False positives burn analysts. False negatives miss campaigns.",
                "blocks": ["Auth logs", "Noise", "Need: detect · triage · prove"],
                "cta": {"label": "Enter product", "route": "/"},
            },
            {
                "id": "contract",
                "kicker": "Design rule",
                "headline": "Observable events only.",
                "line": "Ground truth exists for evaluation — never for detectors or the agent.",
                "blocks": ["AuthEvent", "GT offline", "AST import walls"],
            },
            {
                "id": "detectors",
                "kicker": "Detection",
                "headline": "Rules and ML stay independent.",
                "line": "No hybrid score. Correlation joins on exact event ids.",
                "blocks": ["Bruteforce", "Spraying", "Impossible travel", "ML baseline"],
            },
            {
                "id": "agent",
                "kicker": "Investigation",
                "headline": "A bounded agent — not a chatbot.",
                "line": "Allowlisted read-only tools. Deterministic reviewer. Mock labeled; Haiku optional.",
                "blocks": ["Tools", "Budget", "Verdict", "Review"],
            },
            {
                "id": "product",
                "kicker": "Product surface",
                "headline": "SOC console you can demo live.",
                "line": "Seed → Live triage → Case dossier → Evaluate vs GT.",
                "blocks": ["Console", "Detection Lab", "Cases", "Evaluation"],
                "cta": {"label": "Open console", "route": "/?seed=42&autoseed=1"},
            },
            {
                "id": "pipeline",
                "kicker": "Distributed path",
                "headline": "Five sites. One broker.",
                "line": "Redpanda carries AuthEvents. Worker detects. Prometheus + Grafana watch throughput.",
                "blocks": ["Producers", "Redpanda", "Worker", "Grafana"],
                "cta": {"label": "Open pipeline", "route": "/pipeline"},
            },
            {
                "id": "prove",
                "kicker": "Integrity",
                "headline": "Claims need metrics.",
                "line": "Offline benchmarks and per-case GT scoring. Threat Lab stresses scenarios offline.",
                "blocks": ["Precision", "Recall", "F1", "Case vs GT"],
                "cta": {"label": "Evaluation Lab", "route": "/evaluation"},
            },
            {
                "id": "close",
                "kicker": "Takeaway",
                "headline": "Reproducible. Contained. Honest.",
                "line": "Same seed → same world. Agent cannot remediate or read labels. Mock ≠ LLM.",
                "blocks": ["Synthetic", "Isolated GT", "Independent detectors", "Bounded agent"],
                "cta": {"label": "Start demo path", "route": "/?seed=42&autoseed=1"},
            },
        ],
    }


@router.get("/product/trust")
def trust_model() -> dict[str, Any]:
    return {
        "title": "Trust",
        "bullets": [
            {"title": "Synthetic", "text": "Generated traffic only."},
            {"title": "No labels at runtime", "text": "GT stays offline."},
            {"title": "Contained agent", "text": "Read-only tools."},
            {"title": "Independent detectors", "text": "Rules and ML separate."},
            {"title": "Honest baselines", "text": "Mock ≠ LLM."},
        ],
    }


@router.get("/product/tenants")
def tenants() -> list[dict[str, Any]]:
    return list_tenants()
