"""Evaluation panel data for the dashboard: ground truth is used here, and only here.

Lives in ``evaluation`` so the ground-truth API is allowed. The dashboard's detection
panels import from ``dashboard.view`` and never from this module.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from login_anomaly.evaluation.metrics import confusion, f1, precision, recall
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import GeneratedDataset, generate_with_truth
from login_anomaly.simulation.scenarios import ScenarioPlan


def truth_for(
    seed: int, n_events: int, n_accounts: int, duration_hours: int, plan: ScenarioPlan
) -> GeneratedDataset:
    config = GeneratorConfig(
        seed=seed,
        start_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_hours=duration_hours,
        n_accounts=n_accounts,
        n_events=n_events,
    )
    return generate_with_truth(config, plan)


def comparison_rows(truth: GeneratedDataset, flagged: dict[str, set[str]]) -> list[dict[str, Any]]:
    """Metrics per method against ground truth. Detectors never see these labels."""
    event_ids = [event.event_id for event in truth.events]
    labels = [1 if truth.ground_truth.label_for(event_id).is_malicious else 0 for event_id in event_ids]
    rows: list[dict[str, Any]] = []
    for method, predicted_ids in flagged.items():
        predicted = [1 if event_id in predicted_ids else 0 for event_id in event_ids]
        matrix = confusion(labels, predicted)
        rows.append(
            {
                "method": method,
                "tp": matrix.tp,
                "fp": matrix.fp,
                "fn": matrix.fn,
                "tn": matrix.tn,
                "precision": round(precision(matrix), 4),
                "recall": round(recall(matrix), 4),
                "f1": round(f1(matrix), 4),
            }
        )
    return rows
