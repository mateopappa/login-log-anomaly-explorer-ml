"""Threat Lab runner: execute scenario specs and compare the rule detector with the ML baseline.

Evaluation side only: it generates labelled data, so it lives here, next to the experiment.
Each spec is scored with the experiment's own per-set evaluation (same dataset shape,
metrics, confusion matrices, recall by scenario and false-positive alerts by decoy kind),
so Threat Lab numbers are directly comparable with ``reports/experiment.json``.

Read-only towards the system under test: the model is trained once by the experiment's
``train_baseline`` (or passed in) and only used for prediction; rules and features are
called, never configured; seeds reserved for training and the reviewed evaluation sets are
refused. The investigator is not involved here and receives nothing from this module.

    python -m login_anomaly.evaluation.threat_lab [--out reports/threat_lab.json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from login_anomaly.evaluation.experiment import EVAL_SETS, TRAIN_SEEDS, EvalSet, _evaluate_set, dataset_config, train_baseline
from login_anomaly.threat_lab.specs import ScenarioSpec, build_catalog

RESERVED_SEEDS: frozenset[int] = frozenset(TRAIN_SEEDS) | frozenset(seed for eval_set in EVAL_SETS for seed in eval_set.seeds)
LIMITATIONS: tuple[str, ...] = (
    "Synthetic data only. These numbers do not estimate performance on real logs.",
    "Scenarios use only the generator's existing knobs (campaign counts, decoy counts, attack ranges). Decoy kinds cannot be selected individually.",
    "boundary_* scenarios sit just outside the rule thresholds by design; they favour the ML baseline by construction and do not measure generalization.",
    "The ML baseline is trained on the nominal plan without decoys; scenarios measure its sensitivity, not transfer to real distributions.",
    "Few seeds per scenario. Read the per-seed spread, not a single number.",
)


def _dataset_shape() -> dict[str, Any]:
    config = dataset_config(0)
    return {
        "start_utc": config.start_utc.isoformat(),
        "duration_hours": config.duration_hours,
        "n_accounts": config.n_accounts,
        "n_events": config.n_events,
    }


def run_scenario(spec: ScenarioSpec, model: object) -> dict[str, Any]:
    """Generate, detect and score one spec. Deterministic for the same spec and model."""
    reserved = sorted(RESERVED_SEEDS & set(spec.seeds))
    if reserved:
        raise ValueError(f"scenario {spec.scenario_id!r} uses seeds reserved for training or evaluation sets: {reserved}")
    result = _evaluate_set(EvalSet(spec.scenario_id, spec.description, spec.seeds, spec.plan, spec.ranges), model)
    return {
        "scenario": spec.metadata(),
        "dataset_shape": _dataset_shape(),
        "datasets": result["datasets"],
        "methods": result["methods"],
        "alerts_without_malicious_events_by_rule_and_decoy": result["alerts_without_malicious_events_by_rule_and_decoy"],
    }


def run_lab(specs: tuple[ScenarioSpec, ...], model: object | None = None) -> dict[str, Any]:
    """Run every spec against one model. Trains the experiment's baseline once when no model is given."""
    ids = [spec.scenario_id for spec in specs]
    if len(set(ids)) != len(ids):
        raise ValueError("scenario ids must be unique")
    if model is None:
        model, _, _ = train_baseline()
    return {
        "train_seeds": list(TRAIN_SEEDS),
        "scenarios": [run_scenario(spec, model) for spec in specs],
        "limitations": list(LIMITATIONS),
    }


def comparison_rows(lab: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per scenario: rules versus ML on the same events. For reports and a future dashboard tab."""
    rows = []
    for item in lab["scenarios"]:
        methods = {m["method"]: m for m in item["methods"]}
        rules, ml = methods["rules"], methods["ml"]
        rows.append(
            {
                "scenario_id": item["scenario"]["scenario_id"],
                "strategy": item["scenario"]["strategy"],
                "seeds": len(item["scenario"]["seeds"]),
                "malicious_events": sum(d["malicious_events"] for d in item["datasets"]),
                "rules_f1": rules["f1"],
                "ml_f1": ml["f1"],
                "rules_recall": rules["recall"],
                "ml_recall": ml["recall"],
                "rules_fp": rules["confusion"]["fp"],
                "ml_fp": ml["confusion"]["fp"],
                "rules_f1_range": [rules["f1_min"], rules["f1_max"]],
                "ml_f1_range": [ml["f1_min"], ml["f1_max"]],
                "false_positive_alerts": sum(item["alerts_without_malicious_events_by_rule_and_decoy"].values()),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Threat Lab scenario catalog.")
    parser.add_argument("--out", type=Path, default=None, help="write the full JSON here; prints the comparison table otherwise")
    args = parser.parse_args()
    lab = run_lab(build_catalog())
    if args.out is not None:
        args.out.write_text(json.dumps(lab, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(comparison_rows(lab), indent=2))


if __name__ == "__main__":
    main()
