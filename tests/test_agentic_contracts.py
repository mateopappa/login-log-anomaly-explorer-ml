"""Agentic contracts and tool policy. No model is called; these are data-shape and policy checks."""

import dataclasses
from datetime import datetime, timezone

import pytest

from login_anomaly.agentic.contracts import (
    ALLOWED_READ_ONLY_TOOLS,
    FORBIDDEN_TOOL_NAMES,
    MAX_STEPS,
    MAX_TOOL_CALLS,
    AgentEvaluationResult,
    EvidenceReference,
    InvestigationInput,
    InvestigationResult,
    ToolCallRecord,
    parse_investigation_result,
)

UTC = timezone.utc
T = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


def make_input() -> InvestigationInput:
    return InvestigationInput(
        alert_id="alt-0001",
        rule_id="bruteforce",
        severity="high",
        event_ids=("evt-1", "evt-2"),
        first_seen=T,
        last_seen=T,
    )


def make_result(**overrides: object) -> InvestigationResult:
    fields: dict[str, object] = {
        "alert_id": "alt-0001",
        "verdict": "malicious",
        "confidence": 0.8,
        "evidence": (EvidenceReference(event_id="evt-1", field="outcome", summary="failure"),),
        "tool_calls": (ToolCallRecord(tool_name="get_account_events", arguments={"account_id": "acct-01"}, status="ok"),),
        "justification": "Repeated failures from one source.",
        "limitations": ("Only one account examined.",),
    }
    fields.update(overrides)
    return InvestigationResult(**fields)  # type: ignore[arg-type]


def test_input_contract_has_no_scenario_or_label_fields() -> None:
    names = {f.name for f in dataclasses.fields(InvestigationInput)}
    assert names.isdisjoint({"scenario_type", "campaign_id", "is_malicious", "label", "ground_truth"})


def test_result_fields_are_exact() -> None:
    names = {f.name for f in dataclasses.fields(InvestigationResult)}
    assert names == {
        "alert_id",
        "verdict",
        "confidence",
        "evidence",
        "tool_calls",
        "justification",
        "limitations",
        "risk_level",
        "hypotheses",
    }


def test_valid_result_is_accepted() -> None:
    assert make_result().verdict == "malicious"


@pytest.mark.parametrize("verdict", ["Malicious", "yes", "", None])
def test_verdict_must_be_one_of_three_values(verdict: object) -> None:
    with pytest.raises(ValueError, match="verdict"):
        make_result(verdict=verdict)


@pytest.mark.parametrize("confidence", [-0.1, 1.01, True, "0.5", None])
def test_confidence_must_be_a_probability(confidence: object) -> None:
    with pytest.raises(ValueError, match="confidence"):
        make_result(confidence=confidence)


def test_result_requires_non_empty_justification() -> None:
    with pytest.raises(ValueError, match="justification"):
        make_result(justification="")


def test_evidence_must_be_references_not_free_text() -> None:
    with pytest.raises(ValueError, match="EvidenceReference"):
        make_result(evidence=("evt-1 looked suspicious",))


def test_parse_accepts_well_formed_mapping() -> None:
    raw = {
        "alert_id": "alt-0001",
        "verdict": "benign",
        "confidence": 0.6,
        "evidence": [{"event_id": "evt-1", "field": "country_code", "summary": "AR"}],
        "tool_calls": [{"tool_name": "get_account_events", "arguments": {"account_id": "acct-01"}, "status": "ok"}],
        "justification": "Consistent home-country use.",
        "limitations": [],
    }
    assert parse_investigation_result(raw).verdict == "benign"


@pytest.mark.parametrize(
    "raw",
    [
        {"alert_id": "alt-0001"},  # missing fields
        {"alert_id": "alt-0001", "verdict": "maybe", "confidence": 0.5, "evidence": [], "tool_calls": [], "justification": "x", "limitations": []},
        "not a mapping",
        None,
    ],
)
def test_parse_rejects_malformed_result_with_value_error(raw: object) -> None:
    with pytest.raises(ValueError):
        parse_investigation_result(raw)


def test_tool_policy_constants_are_read_only_and_bounded() -> None:
    assert ALLOWED_READ_ONLY_TOOLS == frozenset(
        {"get_account_events", "get_auth_history", "get_ip_timeline", "get_geo_context", "get_alert_evidence"}
    )
    forbidden_fragments = ("block", "reset", "disable", "delete", "password", "label", "ground_truth")
    assert all(any(fragment in name for fragment in forbidden_fragments) for name in FORBIDDEN_TOOL_NAMES)
    assert ALLOWED_READ_ONLY_TOOLS.isdisjoint(FORBIDDEN_TOOL_NAMES)
    assert MAX_STEPS > 0 and MAX_TOOL_CALLS > 0


def test_agent_evaluation_result_is_a_value_object() -> None:
    result = AgentEvaluationResult(
        alert_id="alt-0001",
        verdict_correct=True,
        unsupported_evidence=0,
        irrelevant_evidence=0,
        forbidden_access_attempts=0,
        tool_limit_violations=0,
        failed_tool_calls=0,
        steps=1,
        cost_usd=None,
        findings=(),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.steps = 2  # type: ignore[misc]
