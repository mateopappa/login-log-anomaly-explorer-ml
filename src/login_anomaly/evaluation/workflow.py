"""Offline scoring for a label-free detection workflow result.

The runtime workflow never receives this module's ``GroundTruth`` input.  This
adapter joins it only after a workflow completes, keeping detector metrics and
investigation-quality metrics as separate result types.
"""

from __future__ import annotations

from dataclasses import dataclass

from login_anomaly.evaluation.agentic import evaluate_investigation, reference_for
from login_anomaly.evaluation.metrics import ConfusionMatrix, confusion
from login_anomaly.simulation.ground_truth import GroundTruth
from login_anomaly.workflow import DetectionWorkflowResult


@dataclass(frozen=True)
class InvestigationQuality:
    """Aggregate quality and policy outcomes for native-alert investigations."""

    alerts: int
    investigated: int
    failed: int
    correct: int
    incorrect: int
    inconclusive: int
    unsupported_evidence: int
    irrelevant_evidence: int
    forbidden_access_attempts: int
    tool_limit_violations: int
    failed_tool_calls: int


@dataclass(frozen=True)
class CaseInvestigationQuality:
    """Offline correctness and safety counts for case-agent results."""

    cases: int
    correct: int
    incorrect: int
    inconclusive: int
    unsupported_evidence: int
    tool_errors: int
    budget_exhausted: int


@dataclass(frozen=True)
class WorkflowEvaluation:
    """Offline metrics for one workflow result and its independently supplied truth."""

    rules: ConfusionMatrix
    ml: ConfusionMatrix
    investigation: InvestigationQuality
    case_investigation: CaseInvestigationQuality


def evaluate_workflow(workflow: DetectionWorkflowResult, truth: GroundTruth) -> WorkflowEvaluation:
    """Score completed workflow outputs without changing the workflow or investigator."""
    labels = [1 if truth.label_for(event_id).is_malicious else 0 for event_id in workflow.event_ids]
    rule_ids = {event_id for alert in workflow.rule_alerts for event_id in alert.event_ids}
    ml_ids = {signal.event_id for signal in workflow.ml_positive_signals}
    rules = confusion(labels, [1 if event_id in rule_ids else 0 for event_id in workflow.event_ids])
    ml = confusion(labels, [1 if event_id in ml_ids else 0 for event_id in workflow.event_ids])

    evaluated = []
    for item in workflow.investigations:
        if item.investigation_input is not None and item.run is not None:
            evaluated.append(evaluate_investigation(item.run.result, reference_for(item.investigation_input, truth), item.investigation_input))

    quality = InvestigationQuality(
        alerts=len(workflow.rule_alerts),
        investigated=len(evaluated),
        failed=len(workflow.rule_alerts) - len(evaluated),
        correct=sum(result.verdict_correct is True for result in evaluated),
        incorrect=sum(result.verdict_correct is False for result in evaluated),
        inconclusive=sum(result.verdict_correct is None for result in evaluated),
        unsupported_evidence=sum(result.unsupported_evidence for result in evaluated),
        irrelevant_evidence=sum(result.irrelevant_evidence for result in evaluated),
        forbidden_access_attempts=sum(result.forbidden_access_attempts for result in evaluated),
        tool_limit_violations=sum(result.tool_limit_violations for result in evaluated),
        failed_tool_calls=sum(result.failed_tool_calls for result in evaluated),
    )
    case_results = workflow.case_investigations
    case_correct = case_incorrect = case_inconclusive = unsupported = tool_errors = budget_exhausted = 0
    for run in case_results:
        expected_malicious = any(truth.label_for(event_id).is_malicious for event_id in run.case.event_ids)
        if run.result.verdict == "inconclusive":
            case_inconclusive += 1
        elif (run.result.verdict == "malicious") == expected_malicious:
            case_correct += 1
        else:
            case_incorrect += 1
        unsupported += sum(item.event_id not in run.case.event_ids for item in run.result.evidence)
        tool_errors += sum(call.status != "ok" for call in run.result.tool_calls)
        budget_exhausted += sum("budget" in error for error in run.errors)
    case_quality = CaseInvestigationQuality(
        cases=len(case_results),
        correct=case_correct,
        incorrect=case_incorrect,
        inconclusive=case_inconclusive,
        unsupported_evidence=unsupported,
        tool_errors=tool_errors,
        budget_exhausted=budget_exhausted,
    )
    return WorkflowEvaluation(rules=rules, ml=ml, investigation=quality, case_investigation=case_quality)
