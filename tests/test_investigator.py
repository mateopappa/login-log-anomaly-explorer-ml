"""Deterministic investigator: real alerts, evidence support, errors, budget, evaluator compatibility.

No language model is involved. The investigator receives events and an InvestigationInput only.
"""

import ast
import dataclasses
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from login_anomaly.agentic import investigator as investigator_module
from login_anomaly.agentic.contracts import (
    ALLOWED_READ_ONLY_TOOLS,
    MAX_STEPS,
    MAX_TOOL_CALLS,
    OBSERVABLE_FIELDS,
    InvestigationInput,
    InvestigationResult,
    parse_investigation_result,
)
from login_anomaly.agentic.investigator import find_alert, investigation_input_for, run_investigation
from login_anomaly.detection.rules import detect
from login_anomaly.evaluation.agentic import AlertReference, evaluate_investigation, reference_for
from login_anomaly.evaluation.experiment import PLAN, dataset_config
from login_anomaly.evaluation.investigation import investigate_dataset, summarize
from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.simulation.generator import generate_with_truth

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def dataset():  # type: ignore[no-untyped-def]
    return generate_with_truth(dataset_config(201), PLAN)


@pytest.fixture(scope="module")
def alerts(dataset):  # type: ignore[no-untyped-def]
    found = detect(dataset.events)
    assert {a.rule_id for a in found} == {"bruteforce", "password_spraying", "impossible_travel"}
    return found


def first(alerts, rule_id: str):  # type: ignore[no-untyped-def]
    return next(a for a in alerts if a.rule_id == rule_id)


def ev(event_id: str, minutes: float, account: str = "acct-01", ip: str = "10.1.1.1",
       outcome: Outcome = Outcome.FAILURE, country: str = "AR") -> AuthEvent:
    return AuthEvent(event_id, T0 + timedelta(minutes=minutes), account, ip, outcome, country)


# --- 1. real alerts from the existing flow ---


@pytest.mark.parametrize("rule_id", ["bruteforce", "password_spraying", "impossible_travel"])
def test_investigates_a_real_alert_of_each_rule(dataset, alerts, rule_id: str) -> None:  # type: ignore[no-untyped-def]
    investigation = investigation_input_for(first(alerts, rule_id))
    run = run_investigation(dataset.events, investigation)
    result = run.result
    assert isinstance(result, InvestigationResult)
    assert result.alert_id == investigation.alert_id
    assert result.verdict in {"malicious", "benign"}
    assert result.tool_calls[0].tool_name == "get_alert_evidence"
    assert all(call.status == "ok" for call in result.tool_calls)
    assert len(result.tool_calls) <= MAX_TOOL_CALLS and run.steps <= MAX_STEPS


def test_find_alert_rejects_an_unknown_alert_id(alerts) -> None:  # type: ignore[no-untyped-def]
    assert find_alert(alerts, alerts[0].alert_id) is alerts[0]
    with pytest.raises(LookupError):
        find_alert(alerts, "alt-9999")


# --- 2. evidence is backed by the data ---


def test_evidence_cites_only_alert_events_and_observable_fields(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    by_id = {e.event_id: e for e in dataset.events}
    for alert in alerts:
        result = run_investigation(dataset.events, investigation_input_for(alert)).result
        assert result.evidence
        for item in result.evidence:
            assert item.event_id in alert.event_ids
            assert item.field in OBSERVABLE_FIELDS
            event = by_id[item.event_id]
            value = getattr(event, item.field)
            assert (value.value if isinstance(value, Outcome) else value) in item.summary


def test_known_source_turns_a_bruteforce_alert_benign() -> None:
    # The same IP logged in successfully to this account before the failures.
    failures = tuple(ev(f"evt-f{i:02d}", 60 + i * 0.5) for i in range(15))
    known = ev("evt-ok", 0, outcome=Outcome.SUCCESS)
    alert = detect((known, *failures))[0]
    result = run_investigation((known, *failures), investigation_input_for(alert)).result
    assert result.verdict == "benign"
    assert "earlier successful login" in result.justification


def test_alert_that_does_not_match_its_events_is_inconclusive() -> None:
    events = (ev("evt-1", 0, outcome=Outcome.SUCCESS), ev("evt-2", 1))
    investigation = InvestigationInput("alt-0001", "bruteforce", "high", ("evt-1", "evt-2"), T0, T0 + timedelta(minutes=1))
    result = run_investigation(events, investigation).result
    assert result.verdict == "inconclusive" and result.confidence == 0.0
    assert result.limitations


# --- 3. tool errors, missing data, unknown ids ---


def test_missing_alert_events_give_inconclusive_without_pivots() -> None:
    investigation = InvestigationInput("alt-0001", "bruteforce", "high", ("evt-x", "evt-y"), T0, T0 + timedelta(minutes=1))
    result = run_investigation((ev("evt-1", 0),), investigation).result
    assert result.verdict == "inconclusive"
    assert [c.tool_name for c in result.tool_calls] == ["get_alert_evidence"]
    assert result.evidence == ()
    assert any("not in the available events" in item for item in result.limitations)


def test_unknown_rule_is_inconclusive() -> None:
    investigation = InvestigationInput("alt-0001", "new_rule", "medium", ("evt-1",), T0, T0)
    result = run_investigation((ev("evt-1", 0),), investigation).result
    assert result.verdict == "inconclusive"
    assert any("No investigation playbook" in item for item in result.limitations)


def test_tool_error_is_recorded_and_blocks_a_verdict(dataset, alerts, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    original = investigator_module.TOOLS["get_account_events"]

    def failing(ctx, **kwargs):  # type: ignore[no-untyped-def]
        record, _ = original(ctx, account_id="no-such-account", start=kwargs["start"], end=kwargs["end"])
        return record, ()

    monkeypatch.setitem(investigator_module.TOOLS, "get_account_events", failing)
    result = run_investigation(dataset.events, investigation_input_for(first(alerts, "bruteforce"))).result
    assert result.verdict == "inconclusive"
    assert [c.status for c in result.tool_calls] == ["ok", "error"]
    assert any("returned an error" in item for item in result.limitations)


# --- 4. effective budget ---


def test_tool_call_limit_is_enforced(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    investigation = investigation_input_for(first(alerts, "impossible_travel"))  # plans 4 calls
    run = run_investigation(dataset.events, investigation, max_tool_calls=2)
    assert len(run.result.tool_calls) == 2
    assert run.result.verdict == "inconclusive"
    assert any("Budget exhausted" in item for item in run.result.limitations)


def test_step_limit_is_enforced_and_reserves_the_conclusion(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    investigation = investigation_input_for(first(alerts, "impossible_travel"))
    run = run_investigation(dataset.events, investigation, max_steps=2)
    assert run.steps == 2
    assert len(run.result.tool_calls) == 1
    assert run.result.verdict == "inconclusive"
    one = run_investigation(dataset.events, investigation, max_steps=1)
    assert one.steps == 1 and one.result.tool_calls == () and one.result.verdict == "inconclusive"


@pytest.mark.parametrize("kwargs", [{"max_steps": MAX_STEPS + 1}, {"max_tool_calls": MAX_TOOL_CALLS + 1}, {"max_steps": 0}, {"max_tool_calls": 0}])
def test_budget_cannot_exceed_the_contract(dataset, alerts, kwargs) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        run_investigation(dataset.events, investigation_input_for(alerts[0]), **kwargs)


# --- 5. compatibility with the contract and the evaluator ---


def test_result_round_trips_through_the_untrusted_parser(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    result = run_investigation(dataset.events, investigation_input_for(alerts[0])).result
    raw = {
        "alert_id": result.alert_id, "verdict": result.verdict, "confidence": result.confidence,
        "evidence": [dataclasses.asdict(e) for e in result.evidence],
        "tool_calls": [{"tool_name": c.tool_name, "arguments": dict(c.arguments), "status": c.status} for c in result.tool_calls],
        "justification": result.justification, "limitations": list(result.limitations),
    }
    assert parse_investigation_result(raw) == result


def test_end_to_end_evaluation_on_the_nominal_set(dataset) -> None:  # type: ignore[no-untyped-def]
    reports = investigate_dataset(dataset)
    assert reports
    for report in reports:
        evaluation = report.evaluation
        assert evaluation.alert_id == report.investigation_input.alert_id
        assert evaluation.unsupported_evidence == 0
        assert evaluation.irrelevant_evidence == 0
        assert evaluation.forbidden_access_attempts == 0
        assert evaluation.tool_limit_violations == 0
        assert evaluation.steps == len(report.run.result.tool_calls)
    summary = summarize(reports)
    assert summary["alerts"] == len(reports)
    assert sum(summary["correctness"].values()) == len(reports)


def test_reference_is_built_from_ground_truth_on_the_evaluation_side(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    investigation = investigation_input_for(first(alerts, "bruteforce"))
    reference = reference_for(investigation, dataset.ground_truth)
    assert reference.alert_id == investigation.alert_id
    assert reference.malicious_event_ids <= set(investigation.event_ids)
    assert reference.is_true_alert == bool(reference.malicious_event_ids)


def test_evaluator_does_not_alter_the_investigation(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    investigation = investigation_input_for(alerts[0])
    result = run_investigation(dataset.events, investigation).result
    snapshot = dataclasses.replace(result)
    evaluate_investigation(result, AlertReference(investigation.alert_id, False, frozenset()), investigation)
    assert result == snapshot


# --- 6. determinism, no side effects, ground-truth isolation ---


def test_runs_are_deterministic_and_independent_of_event_order(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    for alert in alerts:
        investigation = investigation_input_for(alert)
        a = run_investigation(dataset.events, investigation)
        b = run_investigation(tuple(reversed(dataset.events)), investigation)
        assert a == b


def test_investigation_does_not_mutate_its_inputs(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    events = list(dataset.events)
    before = list(events)
    investigation = investigation_input_for(alerts[0])
    run_investigation(events, investigation)
    assert events == before
    assert investigation == investigation_input_for(alerts[0])


def test_investigator_only_calls_allowed_tools(dataset, alerts) -> None:  # type: ignore[no-untyped-def]
    for alert in alerts:
        result = run_investigation(dataset.events, investigation_input_for(alert)).result
        assert {c.tool_name for c in result.tool_calls} <= ALLOWED_READ_ONLY_TOOLS


def test_investigator_module_imports_no_truth_or_generator() -> None:
    tree = ast.parse(Path(investigator_module.__file__).read_text(encoding="utf-8"))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert not any(name.startswith(("login_anomaly.simulation", "login_anomaly.evaluation")) for name in imported)
