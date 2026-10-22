"""Read-only investigation tools: behaviour, limits, errors, field exposure, and no ground truth.

Each tool returns (ToolCallRecord, data). Errors return status "error" and no data.
"""

import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from login_anomaly.agentic.contracts import ALLOWED_READ_ONLY_TOOLS, OBSERVABLE_FIELDS, InvestigationInput
from login_anomaly.agentic.tools import (
    MAX_EVENTS,
    MAX_HISTORY_LIMIT,
    MAX_WINDOW,
    TOOLS,
    ToolContext,
    get_account_events,
    get_alert_evidence,
    get_auth_history,
    get_geo_context,
    get_ip_timeline,
)
from login_anomaly.events import AuthEvent, Outcome

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


def ev(event_id: str, minutes: float, account: str = "acct-01", ip: str = "10.1.1.1",
       outcome: Outcome = Outcome.FAILURE, country: str = "AR") -> AuthEvent:
    return AuthEvent(event_id, T0 + timedelta(minutes=minutes), account, ip, outcome, country)


INVESTIGATION = InvestigationInput(
    alert_id="alt-0001", rule_id="bruteforce", severity="high",
    event_ids=("evt-1", "evt-2"), first_seen=T0, last_seen=T0 + timedelta(minutes=1),
)
EVENTS = (
    ev("evt-1", 0),
    ev("evt-2", 1),
    ev("evt-3", 2, account="acct-02", ip="10.2.2.2", outcome=Outcome.SUCCESS, country="US"),
    ev("evt-4", 3, account="acct-01", ip="10.1.1.1", outcome=Outcome.SUCCESS, country="AR"),
)
CTX = ToolContext(events=EVENTS, investigation=INVESTIGATION)
START, END = T0 - timedelta(hours=1), T0 + timedelta(hours=1)


# --- 1. normal behaviour ---


def test_registry_matches_the_documented_read_only_tools() -> None:
    assert set(TOOLS) == set(ALLOWED_READ_ONLY_TOOLS)


def test_get_account_events_returns_the_account_in_time_order() -> None:
    record, rows = get_account_events(CTX, "acct-01", START, END)
    assert record.status == "ok" and record.tool_name == "get_account_events"
    assert [r["event_id"] for r in rows] == ["evt-1", "evt-2", "evt-4"]


def test_get_auth_history_is_newest_first_and_limited() -> None:
    record, rows = get_auth_history(CTX, "acct-01", 2)
    assert record.status == "ok"
    assert [r["event_id"] for r in rows] == ["evt-4", "evt-2"]


def test_get_ip_timeline_returns_only_that_source() -> None:
    record, rows = get_ip_timeline(CTX, "10.2.2.2", START, END)
    assert record.status == "ok"
    assert [r["event_id"] for r in rows] == ["evt-3"]


def test_get_geo_context_returns_the_region_name() -> None:
    record, rows = get_geo_context(CTX, "JP")
    assert record.status == "ok"
    assert rows == ({"country_code": "JP", "region": "Asia"},)


def test_get_alert_evidence_returns_the_input_alert_only() -> None:
    record, rows = get_alert_evidence(CTX, "alt-0001")
    assert record.status == "ok"
    assert rows[0]["event_ids"] == ("evt-1", "evt-2")
    assert rows[0]["rule_id"] == "bruteforce"


# --- 2. unknown ids and too-wide windows ---


@pytest.mark.parametrize(
    "call",
    [
        lambda: get_account_events(CTX, "acct-99", START, END),
        lambda: get_auth_history(CTX, "acct-99", 5),
        lambda: get_ip_timeline(CTX, "10.9.9.9", START, END),
        lambda: get_geo_context(CTX, "XX"),
        lambda: get_alert_evidence(CTX, "alt-9999"),
    ],
    ids=["account", "history", "ip", "country", "alert"],
)
def test_unknown_ids_return_error_with_no_data(call) -> None:  # type: ignore[no-untyped-def]
    record, rows = call()
    assert record.status == "error"
    assert rows == ()


def test_window_wider_than_seven_days_is_an_error() -> None:
    record, rows = get_account_events(CTX, "acct-01", START, START + MAX_WINDOW + timedelta(seconds=1))
    assert record.status == "error" and rows == ()


def test_reversed_window_is_an_error() -> None:
    record, rows = get_ip_timeline(CTX, "10.1.1.1", END, START)
    assert record.status == "error" and rows == ()


def test_non_utc_window_is_an_error() -> None:
    offset = timezone(timedelta(hours=-3))
    record, _ = get_account_events(CTX, "acct-01", START.astimezone(offset), END)
    assert record.status == "error"


# --- 3. limits and boundaries ---


def test_window_of_exactly_seven_days_is_accepted() -> None:
    record, _ = get_account_events(CTX, "acct-01", START, START + MAX_WINDOW)
    assert record.status == "ok"


@pytest.mark.parametrize("limit", [0, -1, MAX_HISTORY_LIMIT + 1, True, "5", None])
def test_history_limit_outside_range_or_wrong_type_is_an_error(limit: object) -> None:
    record, rows = get_auth_history(CTX, "acct-01", limit)  # type: ignore[arg-type]
    assert record.status == "error" and rows == ()


def test_history_limit_at_maximum_is_accepted() -> None:
    assert get_auth_history(CTX, "acct-01", MAX_HISTORY_LIMIT)[0].status == "ok"


def test_more_than_500_events_is_an_error_not_a_silent_truncation() -> None:
    many = tuple(ev(f"evt-{i:04d}", i * 0.01, account="acct-big") for i in range(MAX_EVENTS + 1))
    record, rows = get_account_events(ToolContext(many, INVESTIGATION), "acct-big", START, END)
    assert record.status == "error" and rows == ()


def test_exactly_500_events_is_accepted() -> None:
    many = tuple(ev(f"evt-{i:04d}", i * 0.01, account="acct-big") for i in range(MAX_EVENTS))
    record, rows = get_account_events(ToolContext(many, INVESTIGATION), "acct-big", START, END)
    assert record.status == "ok" and len(rows) == MAX_EVENTS


def test_non_string_identifier_is_an_error_not_a_crash() -> None:
    record, rows = get_account_events(CTX, None, START, END)  # type: ignore[arg-type]
    assert record.status == "error" and rows == ()


# --- 4. exposed fields and no ground truth ---


def test_rows_expose_exactly_the_observable_fields() -> None:
    _, rows = get_account_events(CTX, "acct-01", START, END)
    assert all(set(row) == set(OBSERVABLE_FIELDS) for row in rows)


def test_context_carries_no_labels() -> None:
    names = {f.name for f in dataclasses.fields(ToolContext)}
    assert names == {"events", "investigation"}


def test_tool_output_has_no_label_fields() -> None:
    forbidden = {"label", "is_malicious", "scenario_type", "campaign_id", "scenario"}
    _, rows = get_account_events(CTX, "acct-01", START, END)
    for row in rows:
        assert forbidden.isdisjoint(row)


# --- 5. access limits for alerts and countries ---


def test_alert_evidence_refuses_an_alert_outside_the_input() -> None:
    record, rows = get_alert_evidence(CTX, "alt-0002")
    assert record.status == "error" and rows == ()


@pytest.mark.parametrize("country", ["AR", "BR", "DE", "JP", "US"])
def test_geo_context_accepts_allowlisted_countries(country: str) -> None:
    assert get_geo_context(CTX, country)[0].status == "ok"


# --- 6. determinism and no side effects ---


def test_same_inputs_give_identical_outputs() -> None:
    assert get_account_events(CTX, "acct-01", START, END) == get_account_events(CTX, "acct-01", START, END)


def test_calls_do_not_change_the_context() -> None:
    before = tuple(EVENTS)
    get_auth_history(CTX, "acct-01", 3)
    get_ip_timeline(CTX, "10.1.1.1", START, END)
    assert tuple(CTX.events) == before


def test_record_arguments_are_strings_as_the_contract_requires() -> None:
    record, _ = get_account_events(CTX, "acct-01", START, END)
    assert all(isinstance(value, str) for value in record.arguments.values())


@pytest.mark.parametrize("country", [["AR"], {"AR"}, 42, None])
def test_non_string_country_is_an_error_not_a_crash(country: object) -> None:
    record, rows = get_geo_context(CTX, country)  # type: ignore[arg-type]
    assert record.status == "error" and rows == ()
