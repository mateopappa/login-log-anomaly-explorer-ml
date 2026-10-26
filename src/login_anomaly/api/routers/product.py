"""Product storytelling contracts: demo path, trust model, multi-site catalog, presenter beats."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from login_anomaly.tenants import list_tenants

router = APIRouter(tags=["product"])


@router.get("/product/demo-path")
def demo_path() -> dict[str, Any]:
    return {
        "title": "Walkthrough",
        "pitch": "Seed traffic → raise alerts → open a case → investigate → score it.",
        "audience": "Proofpoint bootcamp / security engineering demo",
        "presenter_route": "/story",
        "steps": [
            {
                "id": "lab",
                "title": "Seed",
                "route": "/?seed=42&autoseed=1",
                "action": "Load dataset",
                "why": "Fixed seed, repeatable volume.",
            },
            {
                "id": "streams",
                "title": "Ingest",
                "route": "/pipeline",
                "action": "5 site feeds",
                "why": "Broker + rules metrics (no case DB).",
            },
            {
                "id": "live",
                "title": "Triage",
                "route": "/detection?seed=42&autostart=1&rate=8",
                "action": "SOC Live",
                "why": "Release events, watch alerts.",
            },
            {
                "id": "investigate",
                "title": "Investigate",
                "route": "/cases",
                "action": "Open case",
                "why": "Read-only tools only.",
            },
            {
                "id": "score",
                "title": "Score",
                "route": "/evaluation",
                "action": "Run benchmark",
                "why": "Precision, recall, F1.",
            },
            {
                "id": "adversarial",
                "title": "Red team",
                "route": "/threat-lab",
                "action": "One scenario",
                "why": "Offline attack catalog.",
            },
        ],
        "talking_points": [
            "Seed/Live → Postgres cases. Pipeline → rules + Grafana only.",
            "Rules and ML stay separate — no blended score.",
            "Investigator is tool-gated, not free chat.",
            "Mock is explicit; Haiku is optional when a key is set.",
            "Labels never hit detectors or tools.",
        ],
    }


@router.get("/product/story")
def story_beats() -> dict[str, Any]:
    """Presenter beats for /story — on-screen EN, speaker cue ES."""
    return {
        "title": "Login Anomaly Explorer",
        "subtitle": "Synthetic auth telemetry into a triage loop you can audit",
        "controls": "← → or space · Esc exits",
        "beats": [
            {
                "id": "hook",
                "kicker": "Ops reality",
                "headline": "Login noise eats the queue.",
                "line": "Spraying, travel hops, and shared NATs look alike until you correlate them.",
                "blocks": ["Auth logs", "False positives", "Missed campaigns"],
                "say": "Arrancamos desde el dolor del SOC: la cola se llena de logins raros y la mayoría son ruido.",
                "cta": {"label": "Open console", "route": "/"},
            },
            {
                "id": "contract",
                "kicker": "Trust boundary",
                "headline": "Detectors only see observables.",
                "line": "Ground-truth labels stay offline for scoring — never in the runtime path.",
                "blocks": ["AuthEvent", "GT offline", "Import guards"],
                "say": "Contrato duro: reglas y ML solo ven el evento observable. Las etiquetas no entran al runtime.",
            },
            {
                "id": "detectors",
                "kicker": "Detection",
                "headline": "Signature rules next to an ML baseline.",
                "line": "No hybrid fusion. Cases join on exact event ids.",
                "blocks": ["Bruteforce", "Password spray", "Impossible travel", "ML flag"],
                "say": "Dos detectores independientes — firmas y ML. Sin score mezclado. El case junta por event id.",
            },
            {
                "id": "agent",
                "kicker": "Investigation",
                "headline": "Tool-gated investigator.",
                "line": "Allowlisted reads, hard budgets, deterministic review. Mock first; Haiku if configured.",
                "blocks": ["Tool calls", "Budget", "Verdict", "Reviewer"],
                "say": "El investigador no es chat libre: tools de solo lectura, presupuesto, y un reviewer determinístico.",
            },
            {
                "id": "product",
                "kicker": "Console",
                "headline": "Same loop an analyst would run.",
                "line": "Seed → live triage → case dossier → score against labels.",
                "blocks": ["Console", "SOC Live", "Cases", "Scores"],
                "say": "Mismo loop de triage: cargás el dataset, soltás tráfico en Live, abrís el case, scorés contra labels.",
                "cta": {"label": "Load seed 42", "route": "/?seed=42&autoseed=1"},
            },
            {
                "id": "pipeline",
                "kicker": "Multi-site ingest",
                "headline": "Five tenants on one Kafka API.",
                "line": "Redpanda + rules worker + Grafana. Cases still come from seed / Live → Postgres.",
                "blocks": ["Producers", "Redpanda", "Rules metrics", "Grafana"],
                "say": "Multi-sede: cinco tenants a Redpanda, worker de reglas + métricas. Los cases del producto siguen viniendo de seed/Live.",
                "cta": {"label": "Open pipeline", "route": "/pipeline"},
            },
            {
                "id": "score",
                "kicker": "Measurement",
                "headline": "Numbers before claims.",
                "line": "Held-out benchmark plus per-case scoring against rebuilt ground truth.",
                "blocks": ["Precision", "Recall", "F1", "Case vs GT"],
                "say": "Cerramos con métricas: precision/recall/F1 en held-out, y score por case contra ground truth.",
                "cta": {"label": "Open scores", "route": "/evaluation"},
            },
            {
                "id": "close",
                "kicker": "Baseline",
                "headline": "Same seed. Same world. Clear limits.",
                "line": "No remediation tools. Mock is not an LLM. Labels stay offline.",
                "blocks": ["Synthetic data", "Isolated GT", "Separate detectors", "Gated agent"],
                "say": "Demo reproducible: mismo seed, mismos límites. Sin remediación. Mock ≠ Haiku.",
                "cta": {"label": "Open console", "route": "/?seed=42&autoseed=1"},
            },
        ],
    }


@router.get("/product/trust")
def trust_model() -> dict[str, Any]:
    return {
        "title": "Guardrails",
        "bullets": [
            {"title": "Synthetic traffic", "text": "Generated auth only."},
            {"title": "Labels offline", "text": "GT never in runtime."},
            {"title": "Gated tools", "text": "Read-only investigator."},
            {"title": "Separate detectors", "text": "Rules and ML unfused."},
            {"title": "Two paths", "text": "Cases via seed/Live; pipeline = metrics."},
            {"title": "Named baselines", "text": "Mock ≠ Haiku."},
        ],
    }


@router.get("/product/tenants")
def tenants() -> list[dict[str, Any]]:
    return list_tenants()
