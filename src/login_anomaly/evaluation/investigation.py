"""End-to-end investigation run: detect, investigate, evaluate. Evaluation side only.

Flow: generated events -> rule detector -> deterministic investigator (events only) ->
agentic evaluator (with a reference built here from ground truth). The investigator never
receives the ground truth; only this module and the evaluator do.

    python -m login_anomaly.evaluation.investigation --seed 201 [--decoys]

The output is deterministic. No language model is called.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from login_anomaly.agentic.contracts import MAX_STEPS, MAX_TOOL_CALLS, AgentEvaluationResult, InvestigationInput
from login_anomaly.agentic.investigator import AlertInvestigation, InvestigationRun, investigate_alerts
from login_anomaly.detection.rules import detect
from login_anomaly.evaluation.agentic import evaluate_investigation, reference_for
from login_anomaly.evaluation.experiment import PLAN, PLAN_WITH_DECOYS, dataset_config
from login_anomaly.simulation.generator import GeneratedDataset, generate_with_truth
from login_anomaly.simulation.ground_truth import GroundTruth


@dataclass(frozen=True)
class InvestigationReport:
    investigation_input: InvestigationInput
    run: InvestigationRun
    evaluation: AgentEvaluationResult


def evaluate_investigations(
    investigations: tuple[AlertInvestigation, ...], truth: GroundTruth
) -> dict[str, AgentEvaluationResult]:
    """Score each completed investigation, keyed by alert id. Failed ones have no score.

    Read-only on the investigations: labels are used to score, never to filter or change them.
    """
    return {
        item.alert_id: evaluate_investigation(item.run.result, reference_for(item.investigation_input, truth), item.investigation_input)
        for item in investigations
        if item.run is not None and item.investigation_input is not None
    }


def investigate_dataset(
    dataset: GeneratedDataset, *, max_steps: int = MAX_STEPS, max_tool_calls: int = MAX_TOOL_CALLS
) -> list[InvestigationReport]:
    """Investigate and evaluate every rule alert. The investigator gets the events only."""
    investigations = investigate_alerts(dataset.events, detect(dataset.events), max_steps=max_steps, max_tool_calls=max_tool_calls)
    failed = [item.error for item in investigations if item.error is not None]
    if failed:
        raise RuntimeError(f"{len(failed)} investigation(s) failed: {failed[0]}")
    evaluations = evaluate_investigations(investigations, dataset.ground_truth)
    return [
        InvestigationReport(item.investigation_input, item.run, evaluations[item.alert_id])  # type: ignore[arg-type]
        for item in investigations
    ]


def summarize(reports: list[InvestigationReport]) -> dict[str, Any]:
    correctness = Counter({True: "correct", False: "incorrect", None: "inconclusive"}[r.evaluation.verdict_correct] for r in reports)
    return {
        "alerts": len(reports),
        "verdicts": dict(sorted(Counter(r.run.result.verdict for r in reports).items())),
        "correctness": dict(sorted(correctness.items())),
        "unsupported_evidence": sum(r.evaluation.unsupported_evidence for r in reports),
        "forbidden_access_attempts": sum(r.evaluation.forbidden_access_attempts for r in reports),
        "tool_limit_violations": sum(r.evaluation.tool_limit_violations for r in reports),
        "failed_tool_calls": sum(r.evaluation.failed_tool_calls for r in reports),
        "per_alert": [
            {
                "alert_id": r.investigation_input.alert_id,
                "rule_id": r.investigation_input.rule_id,
                "verdict": r.run.result.verdict,
                "confidence": r.run.result.confidence,
                "tool_calls": len(r.run.result.tool_calls),
                "steps": r.run.steps,
                "verdict_correct": r.evaluation.verdict_correct,
                "findings": list(r.evaluation.findings),
            }
            for r in reports
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Investigate and evaluate every rule alert on one generated dataset.")
    parser.add_argument("--seed", type=int, default=201)
    parser.add_argument("--decoys", action="store_true", help="use the plan with benign decoys")
    args = parser.parse_args()
    dataset = generate_with_truth(dataset_config(args.seed), PLAN_WITH_DECOYS if args.decoys else PLAN)
    print(json.dumps(summarize(investigate_dataset(dataset)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
