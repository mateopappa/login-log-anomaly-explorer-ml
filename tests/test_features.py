"""ML baseline features: causal, computed from observable events only, no identifiers."""

import inspect
import random
from datetime import datetime, timedelta, timezone

from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.ml.features import FEATURE_NAMES, feature_matrix

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


def ev(event_id: str, minutes: float, account: str = "acct-01", ip: str = "10.1.1.1",
       outcome: Outcome = Outcome.FAILURE, country: str = "AR") -> AuthEvent:
    return AuthEvent(event_id, T0 + timedelta(minutes=minutes), account, ip, outcome, country)


def column(rows: list[list[float]], name: str) -> list[float]:
    index = FEATURE_NAMES.index(name)
    return [row[index] for row in rows]


def test_feature_function_takes_events_only() -> None:
    parameters = list(inspect.signature(feature_matrix).parameters)
    assert parameters == ["events"]


def test_identifiers_are_not_features() -> None:
    forbidden = {"event_id", "account_id", "source_ip", "campaign_id", "scenario_type", "is_malicious"}
    assert forbidden.isdisjoint(FEATURE_NAMES)


def test_failures_in_trailing_10_minutes_for_same_account_and_ip() -> None:
    events = [ev(f"evt-{i}", minutes=i) for i in range(4)]  # minutes 0,1,2,3
    _, rows = feature_matrix(events)
    assert column(rows, "failures_acct_ip_10min") == [1, 2, 3, 4]


def test_features_are_causal_later_events_do_not_change_earlier_rows() -> None:
    base = [ev("evt-1", 0), ev("evt-2", 5)]
    extended = base + [ev("evt-3", 6)]
    _, rows_base = feature_matrix(base)
    _, rows_extended = feature_matrix(extended)
    assert rows_extended[: len(rows_base)] == rows_base


def test_country_change_flag_uses_previous_event_of_the_same_account() -> None:
    events = [ev("evt-1", 0, outcome=Outcome.SUCCESS, country="AR"), ev("evt-2", 30, outcome=Outcome.SUCCESS, country="US")]
    ids, rows = feature_matrix(events)
    assert ids == ["evt-1", "evt-2"]
    assert column(rows, "country_changed_since_previous") == [0, 1]


def test_distinct_accounts_with_failures_per_ip_over_120_minutes() -> None:
    # Counts accounts that failed from this IP, not every account that touched it.
    events = [ev(f"evt-{i}", minutes=i * 10, account=f"acct-{i:02d}", ip="10.9.9.9") for i in range(5)]
    events.append(ev("evt-ok", minutes=55, account="acct-99", ip="10.9.9.9", outcome=Outcome.SUCCESS))
    _, rows = feature_matrix(events)
    assert column(rows, "distinct_accounts_failed_ip_120min")[:5] == [1, 2, 3, 4, 5]
    assert column(rows, "distinct_accounts_failed_ip_120min")[-1] == 5


def test_output_does_not_depend_on_input_order() -> None:
    events = [ev(f"evt-{i}", minutes=i * 0.5) for i in range(20)]
    shuffled = list(events)
    random.Random(7).shuffle(shuffled)
    assert feature_matrix(events) == feature_matrix(shuffled)
