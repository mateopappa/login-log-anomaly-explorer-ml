"""Agentic Evaluator: scores one investigation result against an independent reference.

It is separate from the conventional evaluator in ``metrics.py``. It checks an
investigator's verdict and evidence, plus its policy behavior: tool use, forbidden
access attempts, limits, and failures. Only this module, not the investigator,
receives the reference. The reference is built from ground truth by the evaluation
side, never by the investigator.

Scope: this checks the harness and the policies on the results it is given. It does
not say anything about how an actual language model reasons.
"""

from __future__ import annotations

from dataclasses import dataclass

from login_anomaly.agentic.contracts import (
    ALLOWED_READ_ONLY_TOOLS,
    FORBIDDEN_ARGUMENT_KEYS,
    FORBIDDEN_TOOL_NAMES,
    MAX_TOOL_CALLS,
    OBSERVABLE_FIELDS,
    AgentEvaluationResult,
    InvestigationInput,
    InvestigationResult,
)


@dataclass(frozen=True)
class AlertReference:
    """Reference for one alert. Built from ground truth in the evaluation side only."""

    alert_id: str
    is_true_alert: bool
    malicious_event_ids: frozenset[str]


def evaluate_investigation(
    result: InvestigationResult,
    reference: AlertReference,
    investigation_input: InvestigationInput,
) -> AgentEvaluationResult:
    # Scoring a verdict against another alert's reference would silently produce a wrong
    # correctness value. That is a caller error, so it fails loudly.
    if reference.alert_id != investigation_input.alert_id:
        raise ValueError(
            f"reference is for {reference.alert_id}, not for the investigated alert {investigation_input.alert_id}; "
            "refusing to score a different alert"
        )
    findings: list[str] = []
    if result.alert_id != investigation_input.alert_id:
        findings.append("result refers to a different alert than the one investigated")

    given_ids = set(investigation_input.event_ids)
    unsupported = sum(1 for item in result.evidence if item.event_id not in given_ids)
    irrelevant = sum(1 for item in result.evidence if item.field not in OBSERVABLE_FIELDS)

    forbidden = 0
    limit_violations = 0
    failed = 0
    for call in result.tool_calls:
        argument_hits = any(key in FORBIDDEN_ARGUMENT_KEYS or str(value) in FORBIDDEN_ARGUMENT_KEYS for key, value in call.arguments.items())
        if call.tool_name in FORBIDDEN_TOOL_NAMES or argument_hits:
            forbidden += 1
        if call.tool_name not in ALLOWED_READ_ONLY_TOOLS:
            limit_violations += 1
        if call.status != "ok":
            failed += 1
    steps = len(result.tool_calls)
    if steps > MAX_TOOL_CALLS:
        limit_violations += 1

    if result.verdict == "inconclusive":
        verdict_correct: bool | None = None
    elif result.verdict == "malicious":
        verdict_correct = reference.is_true_alert
    else:
        verdict_correct = not reference.is_true_alert

    if result.verdict == "malicious" and not result.evidence:
        findings.append("malicious verdict without evidence")
    if unsupported:
        findings.append(f"{unsupported} evidence item(s) cite events outside the investigation input")
    if irrelevant:
        findings.append(f"{irrelevant} evidence item(s) cite fields that are not observable events")
    if forbidden:
        findings.append(f"{forbidden} forbidden access attempt(s)")
    if limit_violations:
        findings.append(f"{limit_violations} tool limit violation(s)")

    return AgentEvaluationResult(
        alert_id=result.alert_id,
        verdict_correct=verdict_correct,
        unsupported_evidence=unsupported,
        irrelevant_evidence=irrelevant,
        forbidden_access_attempts=forbidden,
        tool_limit_violations=limit_violations,
        failed_tool_calls=failed,
        steps=steps,
        cost_usd=None,
        findings=tuple(findings),
    )
