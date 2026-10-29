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
                "why": "Each finished publish becomes cases.",
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
            "Five sites, seed, and Live write the same case queue.",
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
        "controls": "← → or space · N notes · Esc board",
        "beats": [
            {
                "id": "hook",
                "kicker": "The needle",
                "headline": "We put the needle in.",
                "line": "The easy set looks strong. On the edge the rule stops closing, and the investigator can still be wrong.",
                "blocks": ["Seeded attacks", "Easy set", "Edge"],
                "say": "Metimos la aguja nosotros. En el escenario fácil las reglas y el modelo se ven muy bien. En el borde la regla deja de cerrar y el investigador puede equivocarse igual.",
            },
            {
                "id": "agenda",
                "kicker": "Agenda",
                "headline": "Four stops.",
                "line": "What it is. Two scored runs. A short live pass. The limits.",
                "blocks": ["What it is", "Two runs", "Live", "Limits"],
                "say": "Primero qué construimos, después las dos corridas ya puntuadas, un vivo corto, y los límites en voz alta.",
            },
            {
                "id": "system",
                "kicker": "The system",
                "headline": "Labels never enter the tools.",
                "line": "Rules and a Random Forest stay separate. Haiku reads the dossier. It does not detect.",
                "blocks": ["Seeded generator", "Rules", "Random Forest", "Read-only Haiku"],
                "say": "La etiqueta no entra al detector ni al investigador. Reglas y Random Forest, scores separados. Haiku lee el dossier con herramientas de solo lectura.",
            },
            {
                "id": "common",
                "kicker": "Common run",
                "headline": "Mixed campaigns. Seed 42.",
                "line": "1,500 events. Eleven dossiers. Haiku was wrong on none of them.",
                "blocks": ["Rules F1 0.931", "ML F1 0.904", "6 correct", "0 incorrect", "5 inconclusive"],
                "say": "Corrida fácil, mismo motor y mismo seed que el borde. Once dossiers: seis correctos, ninguno incorrecto, cinco inconclusos.",
                "cta": {"label": "Show Scores", "route": "/evaluation"},
            },
            {
                "id": "boundary",
                "kicker": "Boundary run",
                "headline": "Same seed. The rule stops.",
                "line": "1,500 events. Sixty-six dossiers. Rules F1 is 0. The model still sees part of it.",
                "blocks": ["Rules F1 0.000", "ML F1 0.553", "34 correct", "4 incorrect", "28 inconclusive"],
                "say": "Mismo seed, escenario Boundary. La regla cae a cero. El modelo queda en cero cincuenta y cinco. Cuatro investigaciones salieron mal.",
                "cta": {"label": "Show Scores", "route": "/evaluation"},
            },
            {
                "id": "dossier",
                "kicker": "One dossier",
                "headline": "Rule, model, and Haiku agreed.",
                "line": "The label said benign. Zero malicious events in the case.",
                "blocks": ["Password spray", "Said malicious", "Expected benign", "needs_review"],
                "say": "Este es el caso. Haiku lo llamó spray malicioso. La etiqueta dice benigno y no hay ningún evento malicioso.",
                "cta": {"label": "Open dossier", "route": "/cases/case-f68131f0a388a84173f89779"},
            },
            {
                "id": "live",
                "kicker": "Live",
                "headline": "One investigation, not the pile.",
                "line": "Pipeline, a short start, then Score vs labels. If Haiku is slow, open the dossier that is already done.",
                "blocks": ["Pipeline", "One case", "Score vs labels"],
                "say": "En vivo mostramos el pipeline y una sola investigación. Si tarda, volvemos al dossier que ya está hecho.",
                "cta": {"label": "Show pipeline", "route": "/pipeline"},
            },
            {
                "id": "close",
                "kicker": "Limits",
                "headline": "The scored run is the metric.",
                "line": "Synthetic data. The high F1 is optimistic. Boundary is the edge of our rule, not a new attacker.",
                "blocks": ["Synthetic", "Optimistic F1", "Rule edge", "One dossier is an anecdote"],
                "say": "Los datos son sintéticos. El F1 alto es optimista. Boundary es el borde de nuestra regla. Una investigación suelta no es la métrica.",
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
