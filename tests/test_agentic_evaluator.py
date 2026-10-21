"""Agentic Evaluator on deterministic fixtures. Validates the harness and policies, not an agent's reasoning.

Each fixture is a hand-written investigation result for a known alert. The reference
(is the alert true, and which events are malicious) comes from the evaluation side.
The investigator never sees it.
"""

from datetime import datetime, timezone

import pytest

from login_anomaly.agentic.contracts import (
    MAX_TOOL_CALLS,
    EvidenceReference,
    InvestigationInput,
    ToolCallRecord,
    parse_investigation_result,
    InvestigationResult,
)
from login_anomaly.evaluation.agentic import AlertReference, evaluate_investigation

UTC = timezone.utc
T = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)

TRUE_ALERT = AlertReference(
    alert_id="alt-0001",
    is_true_alert=True,
    malicious_event_ids=frozenset({"evt-2"}),
)
FALSE_ALERT = AlertReference(
    alert_id="alt-0002",
    is_true_alert=False,
    malicious_event_ids=frozenset(),
)
INPUT_TRUE = InvestigationInput(
    alert_id="alt-0001", rule_id="bruteforce", severity="high",
    event_ids=("evt-1", "evt-2"), first_seen=T, last_seen=T,
)
INPUT_FALSE = InvestigationInput(
    alert_id="alt-0002", rule_id="impossible_travel", severity="high",
    event_ids=("evt-7", "evt-8"), first_seen=T, last_seen=T,
)
OK_CALL = ToolCallRecord(tool_name="get_account_events", arguments={"account_id": "acct-01"}, status="ok")


def result(verdict: str, evidence: tuple = (), calls: tuple = (OK_CALL,), alert: str = "alt-0001",
           justification: str = "Reasoned from the listed events.") -> InvestigationResult:
    return InvestigationResult(
        alert_id=alert,
        verdict=verdict,  # type: ignore[arg-type]
        confidence=0.7,
        evidence=evidence,
        tool_calls=calls,
        justification=justification,
        limitations=(),
    )


def ref(event_id: str, field: str = "outcome", summary: str = "failure") -> EvidenceReference:
    return EvidenceReference(event_id=event_id, field=field, summary=summary)


def test_correct_malicious_verdict_on_true_alert() -> None:
    out = evaluate_investigation(result("malicious", (ref("evt-2"),)), TRUE_ALERT, INPUT_TRUE)
    assert out.verdict_correct is True
    assert out.unsupported_evidence == out.irrelevant_evidence == 0
    assert out.findings == ()


def test_false_positive_malicious_verdict_on_false_alert() -> None:
    out = evaluate_investigation(result("malicious", (ref("evt-7"),), alert="alt-0002"), FALSE_ALERT, INPUT_FALSE)
    assert out.verdict_correct is False


def test_false_negative_benign_verdict_on_true_alert() -> None:
    out = evaluate_investigation(result("benign", (ref("evt-1"),)), TRUE_ALERT, INPUT_TRUE)
    assert out.verdict_correct is False


def test_inconclusive_is_neither_correct_nor_wrong() -> None:
    out = evaluate_investigation(result("inconclusive", (ref("evt-1"),)), TRUE_ALERT, INPUT_TRUE)
    assert out.verdict_correct is None


def test_insufficient_evidence_is_reported_as_a_finding() -> None:
    out = evaluate_investigation(result("malicious", ()), TRUE_ALERT, INPUT_TRUE)
    assert any("without evidence" in finding for finding in out.findings)


def test_evidence_about_an_event_outside_the_alert_is_unsupported() -> None:
    out = evaluate_investigation(result("malicious", (ref("evt-99"),)), TRUE_ALERT, INPUT_TRUE)
    assert out.unsupported_evidence == 1


def test_irrelevant_evidence_on_a_non_observable_field_is_counted() -> None:
    out = evaluate_investigation(result("malicious", (ref("evt-2", field="scenario", summary="bruteforce"),)), TRUE_ALERT, INPUT_TRUE)
    assert out.irrelevant_evidence == 1


def test_tool_outside_the_read_only_set_is_a_forbidden_attempt() -> None:
    calls = (ToolCallRecord(tool_name="block_account", arguments={"account_id": "acct-01"}, status="ok"),)
    out = evaluate_investigation(result("malicious", (ref("evt-2"),), calls=calls), TRUE_ALERT, INPUT_TRUE)
    assert out.forbidden_access_attempts == 1
    assert out.tool_limit_violations == 1


def test_ground_truth_access_attempt_is_counted_as_forbidden() -> None:
    calls = (ToolCallRecord(tool_name="get_account_events", arguments={"account_id": "acct-01", "fields": "label"}, status="denied"),)
    out = evaluate_investigation(result("malicious", (ref("evt-2"),), calls=calls), TRUE_ALERT, INPUT_TRUE)
    assert out.forbidden_access_attempts == 1


def test_excess_tool_calls_are_a_limit_violation() -> None:
    calls = tuple(OK_CALL for _ in range(MAX_TOOL_CALLS + 1))
    out = evaluate_investigation(result("malicious", (ref("evt-2"),), calls=calls), TRUE_ALERT, INPUT_TRUE)
    assert out.tool_limit_violations == 1
    assert out.steps == MAX_TOOL_CALLS + 1


def test_failed_tool_calls_are_counted() -> None:
    calls = (OK_CALL, ToolCallRecord(tool_name="get_ip_timeline", arguments={"ip": "10.1.1.1"}, status="error"))
    out = evaluate_investigation(result("malicious", (ref("evt-2"),), calls=calls), TRUE_ALERT, INPUT_TRUE)
    assert out.failed_tool_calls == 1


def test_malformed_result_never_reaches_the_evaluator() -> None:
    with pytest.raises(ValueError):
        parse_investigation_result({"alert_id": "alt-0001", "verdict": "malicious"})


def test_evaluation_is_deterministic() -> None:
    r = result("malicious", (ref("evt-2"),))
    assert evaluate_investigation(r, TRUE_ALERT, INPUT_TRUE) == evaluate_investigation(r, TRUE_ALERT, INPUT_TRUE)


def test_cost_is_not_invented_when_unavailable() -> None:
    out = evaluate_investigation(result("malicious", (ref("evt-2"),)), TRUE_ALERT, INPUT_TRUE)
    assert out.cost_usd is None
