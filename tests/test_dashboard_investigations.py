"""Investigations in the dashboard view layer (no Streamlit): integration, selection, separation, failures."""

import ast
import dataclasses
from datetime import datetime, timezone
from pathlib import Path

import pytest

from login_anomaly.agentic.investigator import AlertInvestigation, investigate_alerts
from login_anomaly.dashboard import view as view_module
from login_anomaly.dashboard.view import (
    COMPONENT_STATUS,
    SessionConfig,
    events_for,
    investigation_detail,
    investigation_rows,
    investigation_summary,
    investigations_for,
    rule_alerts,
)
from login_anomaly.detection.rules import Alert, Severity
from login_anomaly.evaluation.investigation import evaluate_investigations
from login_anomaly.evaluation.panel import truth_for
from login_anomaly.simulation.scenarios import ScenarioPlan

PLAN = ScenarioPlan(bruteforce_campaigns=2, password_spraying_campaigns=1, impossible_travel_campaigns=2, benign_travelers=2)
SESSION = SessionConfig(seed=31, n_events=1500, n_accounts=150, duration_hours=72, plan=PLAN)
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def events():  # type: ignore[no-untyped-def]
    return events_for(SESSION)


@pytest.fixture(scope="module")
def alerts(events):  # type: ignore[no-untyped-def]
    found = rule_alerts(events)
    assert found
    return found


@pytest.fixture(scope="module")
def investigations(events, alerts):  # type: ignore[no-untyped-def]
    return investigations_for(events, alerts)


@pytest.fixture(scope="module")
def evaluations(investigations):  # type: ignore[no-untyped-def]
    truth = truth_for(SESSION.seed, SESSION.n_events, SESSION.n_accounts, SESSION.duration_hours, SESSION.plan)
    return evaluate_investigations(investigations, truth.ground_truth)


def broken_alert() -> Alert:
    return Alert("alt-bad", "bruteforce", Severity.HIGH, (), T0, T0, (), "")


# --- integration with the existing pipeline ---


def test_every_rule_alert_is_investigated_by_the_existing_investigator(events, alerts, investigations) -> None:  # type: ignore[no-untyped-def]
    assert [i.alert_id for i in investigations] == [a.alert_id for a in alerts]
    assert investigations == investigate_alerts(events.events, alerts)  # same pipeline, no copy of its logic
    assert all(i.run is not None and i.error is None for i in investigations)


def test_summary_counts_verdicts_and_evaluation(investigations, evaluations) -> None:  # type: ignore[no-untyped-def]
    summary = investigation_summary(investigations, evaluations)
    assert summary["alerts"] == summary["investigated"] == len(investigations)
    assert summary["malicious"] + summary["benign"] + summary["inconclusive"] == summary["investigated"]
    scored = summary["evaluation"]
    assert scored["scored"] == len(investigations)
    assert scored["correct"] + scored["incorrect"] + scored["inconclusive"] == scored["scored"]
    assert "evaluation" not in investigation_summary(investigations)


def test_rows_and_detail_for_a_selected_alert(investigations, evaluations) -> None:  # type: ignore[no-untyped-def]
    rows = investigation_rows(investigations, evaluations)
    assert [r["alert_id"] for r in rows] == [i.alert_id for i in investigations]
    assert "evaluation" not in investigation_rows(investigations)[0]
    item = investigations[-1]
    detail = investigation_detail(item, evaluations[item.alert_id])
    assert detail["alert_id"] == item.alert_id and detail["status"] == "completed"
    assert detail["justification"] == item.run.result.justification
    assert [e["event_id"] for e in detail["evidence"]] == [e.event_id for e in item.run.result.evidence]
    assert [c["tool"] for c in detail["tool_calls"]] == [c.tool_name for c in item.run.result.tool_calls]
    assert detail["budget"]["tool_calls"] <= detail["budget"]["max_tool_calls"]
    assert detail["evaluation"]["alert_id"] == item.alert_id
    assert investigation_detail(item)["evaluation"] is None


# --- separation between detection, investigation and evaluation ---


def test_investigations_are_identical_with_or_without_evaluation(events, alerts, investigations, evaluations) -> None:  # type: ignore[no-untyped-def]
    snapshot = tuple(dataclasses.replace(i) for i in investigations)
    evaluate_investigations(investigations, truth_for(SESSION.seed, SESSION.n_events, SESSION.n_accounts, SESSION.duration_hours, SESSION.plan).ground_truth)
    assert investigations == snapshot == investigations_for(events, alerts)
    assert set(evaluations) == {i.alert_id for i in investigations}  # labels never filter investigations


def test_ml_is_marked_as_not_investigated() -> None:
    ml = next(row for row in COMPONENT_STATUS if row["component"] == "ML detector")
    assert "Not investigated" in ml["note"]
    pending = {row["component"] for row in COMPONENT_STATUS if row["status"] == "Pending"}
    assert pending == {"Investigator (LLM)", "Threat Simulation Agent"}


def test_view_module_gives_the_investigator_events_only() -> None:
    tree = ast.parse(Path(view_module.__file__).read_text(encoding="utf-8"))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert not any(name.startswith("login_anomaly.evaluation") for name in imported)
    assert "login_anomaly.simulation.ground_truth" not in imported


# --- no alerts and failed investigations ---


def test_no_alerts_gives_an_empty_summary(events) -> None:  # type: ignore[no-untyped-def]
    empty = investigations_for(events, [])
    assert empty == ()
    summary = investigation_summary(empty, {})
    assert summary["alerts"] == 0 and summary["evaluation"]["scored"] == 0
    assert investigation_rows(empty, {}) == []


def test_failed_investigation_is_reported_not_raised(events, alerts) -> None:  # type: ignore[no-untyped-def]
    mixed = investigations_for(events, [alerts[0], broken_alert()])
    failed = mixed[1]
    assert isinstance(failed, AlertInvestigation) and failed.run is None and "event_ids" in failed.error
    assert mixed[0].run is not None  # one failure does not stop the others
    summary = investigation_summary(mixed)
    assert summary["failed"] == 1 and summary["investigated"] == 1
    assert investigation_rows(mixed)[1]["status"] == "failed"
    detail = investigation_detail(failed)
    assert detail["status"] == "failed" and detail["error"] == failed.error and detail["evaluation"] is None


def test_failed_investigations_are_not_scored(events, alerts) -> None:  # type: ignore[no-untyped-def]
    mixed = investigations_for(events, [alerts[0], broken_alert()])
    truth = truth_for(SESSION.seed, SESSION.n_events, SESSION.n_accounts, SESSION.duration_hours, SESSION.plan)
    scored = evaluate_investigations(mixed, truth.ground_truth)
    assert set(scored) == {alerts[0].alert_id}
    assert investigation_rows(mixed, scored)[1]["evaluation"] == "not scored"


def test_budget_limit_is_visible_in_rows_and_detail(events, alerts) -> None:  # type: ignore[no-untyped-def]
    limited = investigate_alerts(events.events, alerts, max_tool_calls=1)
    assert any(i.run.refused_tools for i in limited)
    row = next(r for r, i in zip(investigation_rows(limited), limited) if i.run.refused_tools)
    assert row["status"] == "limit reached"
    assert investigation_summary(limited)["limit_reached"] >= 1


def test_bad_budget_raises_once_instead_of_failing_every_alert(events, alerts) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        investigate_alerts(events.events, alerts, max_tool_calls=0)
