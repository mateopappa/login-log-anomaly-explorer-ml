"""HTTP-facing offline benchmark helpers. Lives in evaluation so ground truth is allowed."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from login_anomaly.agentic.provider import InvestigatorProvider
from login_anomaly.evaluation.metrics import f1, precision, recall
from login_anomaly.evaluation.workflow import evaluate_workflow
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import EventDataset, generate_with_truth
from login_anomaly.simulation.scenarios import ScenarioPlan
from login_anomaly.workflow import ModelRunMetadata, run_detection_workflow


def run_offline_benchmark(
    *,
    seed: int,
    model: object,
    provider: InvestigatorProvider,
) -> dict[str, Any]:
    plan = ScenarioPlan(
        bruteforce_campaigns=2,
        password_spraying_campaigns=1,
        impossible_travel_campaigns=2,
        benign_travelers=2,
    )
    config = GeneratorConfig(
        seed=seed,
        start_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_hours=72,
        n_accounts=40,
        n_events=800,
    )
    truth_dataset = generate_with_truth(config, plan)
    events_only = EventDataset(truth_dataset.events, truth_dataset.manifest)
    workflow = run_detection_workflow(
        events_only,
        model,
        ModelRunMetadata("eval-rf-baseline"),
        investigator_provider=provider,
    )
    scored = evaluate_workflow(workflow, truth_dataset.ground_truth)

    def _cm(matrix: Any) -> dict[str, Any]:
        return {
            "precision": round(precision(matrix), 4),
            "recall": round(recall(matrix), 4),
            "f1": round(f1(matrix), 4),
            "tp": matrix.tp,
            "fp": matrix.fp,
            "fn": matrix.fn,
            "tn": matrix.tn,
        }

    return {
        "provider_mode": provider.mode,
        "provider_id": provider.provider_id,
        "rules": _cm(scored.rules),
        "ml": _cm(scored.ml),
        "case_investigations": {
            "total": scored.case_investigation.cases,
            "correct": scored.case_investigation.correct,
            "incorrect": scored.case_investigation.incorrect,
            "inconclusive": scored.case_investigation.inconclusive,
        },
        "config": {"seed": seed, "n_events": config.n_events, "duration_hours": config.duration_hours},
    }
