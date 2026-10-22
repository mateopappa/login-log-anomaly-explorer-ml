"""Reproducible comparison of the trivial baseline, the rule detector, and the ML baseline.

The ML model is trained once, on TRAIN_SEEDS with the nominal plan and no decoys.
Every evaluation set is generated from seeds that never appear in training, so
campaigns, accounts and IPs do not cross the split.

Evaluation sets:

- ``nominal``: the same specification as the rule thresholds. Optimistic by construction.
  It is kept as a control, so its numbers can be compared with earlier runs.
- ``nominal_with_decoys``: the same campaigns, plus benign decoys that partly look like attacks.
- ``boundary_stress_with_decoys``: a boundary stress test. Campaign settings sit just outside the rule
  thresholds (HARD_RANGES), plus decoys. It is not a generalization test.
  The model never saw this distribution. This is the set that tests whether the results
  depend on the thresholds.

Campaign ids repeat across datasets ("camp-bf-0001" in several), so metrics are computed
per dataset and summed, never by joining on ids across datasets.

Run: python -m login_anomaly.evaluation.experiment --out reports/experiment.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from login_anomaly.evaluation.workflow import CaseInvestigationQuality, InvestigationQuality, evaluate_workflow
from login_anomaly.evaluation.metrics import ConfusionMatrix, confusion, f1, precision, recall
from login_anomaly.ml.features import feature_matrix
from login_anomaly.ml.model import train_model
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import EventDataset, GeneratedDataset, generate_with_truth
from login_anomaly.simulation.ground_truth import ScenarioType
from login_anomaly.simulation.scenarios import HARD_RANGES, NOMINAL_RANGES, ScenarioPlan, ScenarioRanges
from login_anomaly.workflow import ModelRunMetadata, run_detection_workflow

TRAIN_SEEDS: tuple[int, ...] = (101, 102, 103, 104)
MODEL_SEED = 7
MODEL_RUN_ID = "rf-baseline-7"
PLAN = ScenarioPlan(
    bruteforce_campaigns=3,
    password_spraying_campaigns=2,
    impossible_travel_campaigns=3,
    benign_travelers=5,
)
PLAN_WITH_DECOYS = ScenarioPlan(
    bruteforce_campaigns=3,
    password_spraying_campaigns=2,
    impossible_travel_campaigns=3,
    benign_travelers=5,
    benign_decoys=6,
)


@dataclass(frozen=True)
class EvalSet:
    name: str
    description: str
    seeds: tuple[int, ...]
    plan: ScenarioPlan
    ranges: ScenarioRanges


EVAL_SETS: tuple[EvalSet, ...] = (
    EvalSet(
        name="nominal",
        description="Same specification as the rule thresholds. Optimistic by construction; kept as a control.",
        seeds=(201, 202),
        plan=PLAN,
        ranges=NOMINAL_RANGES,
    ),
    EvalSet(
        name="nominal_with_decoys",
        description="Nominal campaigns plus benign decoys that partly resemble attacks.",
        seeds=(211, 212),
        plan=PLAN_WITH_DECOYS,
        ranges=NOMINAL_RANGES,
    ),
    EvalSet(
        name="boundary_stress_with_decoys",
        description=(
            "BOUNDARY STRESS TEST. Campaign settings sit deliberately just outside the rule thresholds "
            "(14 failures, 9 accounts, 61+ minute gaps). It measures how fast rules fail at their edge. "
            "It is not evidence of generalization to real attacker behaviour, and it favours the ML baseline by construction."
        ),
        seeds=(301, 302, 303),
        plan=PLAN_WITH_DECOYS,
        ranges=HARD_RANGES,
    ),
)


def dataset_config(seed: int) -> GeneratorConfig:
    return GeneratorConfig(
        seed=seed,
        start_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_hours=72,
        n_accounts=200,
        n_events=3000,
    )


@dataclass(frozen=True)
class LabelledRows:
    """Features and labels for one dataset, in canonical event order. Labels are for evaluation."""

    ids: list[str]
    features: list[list[float]]
    labels: list[int]
    scenarios: list[ScenarioType]


def labelled_rows(dataset: GeneratedDataset) -> LabelledRows:
    ids, features = feature_matrix(dataset.events)
    labels = []
    scenarios = []
    for event_id in ids:
        label = dataset.ground_truth.label_for(event_id)
        labels.append(1 if label.is_malicious else 0)
        scenarios.append(label.scenario_type)
    return LabelledRows(ids=ids, features=features, labels=labels, scenarios=scenarios)


def _sum(matrices: list[ConfusionMatrix]) -> ConfusionMatrix:
    return ConfusionMatrix(
        tp=sum(m.tp for m in matrices),
        fp=sum(m.fp for m in matrices),
        fn=sum(m.fn for m in matrices),
        tn=sum(m.tn for m in matrices),
    )


def _metric_row(matrix: ConfusionMatrix) -> dict[str, object]:
    return {
        "confusion": asdict(matrix),
        "precision": round(precision(matrix), 4),
        "recall": round(recall(matrix), 4),
        "f1": round(f1(matrix), 4),
        "flagged_events": matrix.tp + matrix.fp,
    }


def _sum_investigations(items: list[InvestigationQuality]) -> dict[str, int]:
    return {
        field: sum(getattr(item, field) for item in items)
        for field in InvestigationQuality.__dataclass_fields__
    }


def _sum_case_investigations(items: list[CaseInvestigationQuality]) -> dict[str, int]:
    return {
        field: sum(getattr(item, field) for item in items)
        for field in CaseInvestigationQuality.__dataclass_fields__
    }


def train_baseline(train_seeds: tuple[int, ...] = TRAIN_SEEDS) -> tuple[object, int, int]:
    """Train the ML baseline on the training seeds. Returns the model and its row/positive counts."""
    train_x: list[list[float]] = []
    train_y: list[int] = []
    for seed in train_seeds:
        rows = labelled_rows(generate_with_truth(dataset_config(seed), PLAN))
        train_x += rows.features
        train_y += rows.labels
    return train_model(train_x, train_y, seed=MODEL_SEED), len(train_y), sum(train_y)


def _evaluate_set(eval_set: EvalSet, model: object) -> dict[str, Any]:
    per_method: dict[str, list[ConfusionMatrix]] = {"all_benign": [], "rules": [], "ml": []}
    per_seed_f1: dict[str, list[float]] = {"all_benign": [], "rules": [], "ml": []}
    scenario_hits: dict[str, dict[str, list[int]]] = {"all_benign": {}, "rules": {}, "ml": {}}
    false_positive_alerts: Counter[str] = Counter()
    investigation_quality: list[InvestigationQuality] = []
    case_investigation_quality: list[CaseInvestigationQuality] = []
    datasets: list[dict[str, Any]] = []

    for seed in eval_set.seeds:
        dataset = generate_with_truth(dataset_config(seed), eval_set.plan, eval_set.ranges)
        rows = labelled_rows(dataset)
        workflow = run_detection_workflow(
            EventDataset(dataset.events, dataset.manifest), model, ModelRunMetadata(MODEL_RUN_ID)  # type: ignore[arg-type]
        )
        workflow_evaluation = evaluate_workflow(workflow, dataset.ground_truth)
        investigation_quality.append(workflow_evaluation.investigation)
        case_investigation_quality.append(workflow_evaluation.case_investigation)
        rule_flags = {event_id for alert in workflow.rule_alerts for event_id in alert.event_ids}
        ml_flags = {signal.event_id for signal in workflow.ml_positive_signals}
        malicious_ids = {event_id for event_id, label in zip(rows.ids, rows.labels) if label}
        for alert in workflow.rule_alerts:
            if not set(alert.event_ids) & malicious_ids:
                kinds = sorted({dataset.decoy_kinds[e] for e in alert.event_ids if e in dataset.decoy_kinds})
                false_positive_alerts[f"{alert.rule_id}/{','.join(kinds) or 'background'}"] += 1

        predictions = {
            "all_benign": [0] * len(rows.ids),
            "rules": [1 if event_id in rule_flags else 0 for event_id in rows.ids],
            "ml": [1 if event_id in ml_flags else 0 for event_id in rows.ids],
        }
        for method, predicted in predictions.items():
            matrix = confusion(rows.labels, predicted)
            per_method[method].append(matrix)
            per_seed_f1[method].append(round(f1(matrix), 4))
            for scenario, truth, guess in zip(rows.scenarios, rows.labels, predicted):
                if truth == 1:
                    hits = scenario_hits[method].setdefault(scenario.value, [0, 0])
                    hits[1] += 1
                    hits[0] += guess
        datasets.append(
            {
                "seed": seed,
                "events": len(rows.ids),
                "malicious_events": sum(rows.labels),
                "campaigns": len({
                    dataset.ground_truth.label_for(e.event_id).campaign_id
                    for e in dataset.events
                    if dataset.ground_truth.label_for(e.event_id).campaign_id is not None
                }),
                "class_distribution": {str(k): v for k, v in sorted(Counter(rows.labels).items())},
                "workflow": {
                    "dataset_id": workflow.dataset_id,
                    "rule_alerts": len(workflow.rule_alerts),
                    "ml_positive_events": len(workflow.ml_positive_signals),
                    "cases": {
                        "rule_backed": sum(case.case_kind == "rule_backed" for case in workflow.cases),
                        "ml_only": sum(case.case_kind == "ml_only" for case in workflow.cases),
                        "execution_mode": workflow.case_investigations[0].mode if workflow.case_investigations else "mock",
                    },
                    "detectors": {
                        "rules": _metric_row(workflow_evaluation.rules),
                        "ml": _metric_row(workflow_evaluation.ml),
                    },
                    "investigation": asdict(workflow_evaluation.investigation),
                    "case_investigation": asdict(workflow_evaluation.case_investigation),
                },
            }
        )

    methods = []
    for method in ("all_benign", "rules", "ml"):
        matrix = _sum(per_method[method])
        by_scenario = {key: hits[0] / hits[1] for key, hits in scenario_hits[method].items() if hits[1]}
        scores = per_seed_f1[method]
        methods.append(
            {
                "method": method,
                "confusion": asdict(matrix),
                "precision": round(precision(matrix), 4),
                "recall": round(recall(matrix), 4),
                "f1": round(f1(matrix), 4),
                # Share of benign events flagged. A high recall with a high flag rate is not a good detector.
                "false_positive_rate": round(matrix.fp / (matrix.fp + matrix.tn), 4) if matrix.fp + matrix.tn else 0.0,
                "flagged_events": matrix.tp + matrix.fp,
                "f1_per_seed": scores,
                "f1_mean": round(statistics.fmean(scores), 4),
                "f1_min": min(scores),
                "f1_max": max(scores),
                "recall_by_scenario": {key: round(value, 4) for key, value in sorted(by_scenario.items())},
            }
        )

    return {
        "name": eval_set.name,
        "description": eval_set.description,
        "seeds": list(eval_set.seeds),
        "plan": asdict(eval_set.plan),
        "ranges": asdict(eval_set.ranges),
        "ranges_are_nominal": eval_set.ranges == NOMINAL_RANGES,
        "datasets": datasets,
        "methods": methods,
        "investigation": _sum_investigations(investigation_quality),
        "case_investigation": _sum_case_investigations(case_investigation_quality),
        "alerts_without_malicious_events_by_rule_and_decoy": dict(sorted(false_positive_alerts.items())),
    }


def run_experiment(
    train_seeds: tuple[int, ...] = TRAIN_SEEDS, eval_sets: tuple[EvalSet, ...] = EVAL_SETS
) -> dict[str, object]:
    used = set(train_seeds)
    for eval_set in eval_sets:
        if used & set(eval_set.seeds):
            raise ValueError(f"seeds of evaluation set {eval_set.name!r} overlap with earlier sets or training")
        used |= set(eval_set.seeds)

    model, train_rows, train_positive = train_baseline(train_seeds)
    sets = [_evaluate_set(eval_set, model) for eval_set in eval_sets]
    return {
        "config": {
            "train_seeds": list(train_seeds),
            "train_plan": asdict(PLAN),
            "model": "RandomForestClassifier (sklearn), class_weight=balanced",
            "model_seed": MODEL_SEED,
            "n_events_per_dataset": 3000,
            "duration_hours": 72,
            "n_accounts": 200,
        },
        "train_rows": train_rows,
        "train_positive_rows": train_positive,
        "evaluation_sets": sets,
        "limitations": [
            "Synthetic data only. These numbers do not estimate performance on real logs.",
            "The nominal set shares its thresholds with the rule detector, so its rule results are optimistic by construction.",
            "The boundary_stress set is a single boundary test. Its ranges sit next to the rule thresholds by design, so the rule collapse it shows follows from that design. It is not a measure of generalization.",
            "The ML model is trained only on the nominal specification without decoys, so the stress set measures sensitivity, not transfer to a new real distribution.",
            "Few campaigns per dataset, so one campaign moves recall noticeably. Use the per-seed spread, not a single number.",
            "Benign background traffic has no diurnal, session, or device structure.",
            "Decoys are assumed, not observed: their kinds and ranges encode what the team expects benign look-alikes to be. False-positive counts per decoy kind show where the rules and the model react, not how often that happens in real life.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the reproducible detector comparison.")
    parser.add_argument("--out", type=Path, required=True, help="path of the JSON result file")
    args = parser.parse_args()
    result = run_experiment()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for eval_set in result["evaluation_sets"]:  # type: ignore[union-attr]
        print(f"[{eval_set['name']}]")  # type: ignore[index]
        for method in eval_set["methods"]:  # type: ignore[index]
            print(
                f"  {method['method']:>10}  P={method['precision']:.3f}  R={method['recall']:.3f}  "
                f"F1={method['f1']:.3f}  F1 min..max={method['f1_min']:.3f}..{method['f1_max']:.3f}"
            )


if __name__ == "__main__":
    main()
