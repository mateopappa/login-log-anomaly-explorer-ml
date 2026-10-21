"""Rule-based detector: one rule per malicious signature, with negatives and false-positive checks.

The detector receives only AuthEvent objects. It never sees labels, so these tests
build events directly and check alerts against the events themselves.
"""

import random
from datetime import datetime, timedelta, timezone

import pytest

from login_anomaly.detection.rules import Alert, Severity, detect
from login_anomaly.events import AuthEvent, Outcome

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


def ev(
    event_id: str,
    minutes: float,
    account: str = "acct-01",
    ip: str = "10.1.1.1",
    outcome: Outcome = Outcome.FAILURE,
    country: str = "AR",
) -> AuthEvent:
    return AuthEvent(
        event_id=event_id,
        timestamp_utc=T0 + timedelta(minutes=minutes),
        account_id=account,
        source_ip=ip,
        outcome=outcome,
        country_code=country,
    )


def rules_fired(alerts: list[Alert]) -> set[str]:
    return {alert.rule_id for alert in alerts}


# --- bruteforce: 15 or more failures on one account from one IP within 10 minutes ---


def test_bruteforce_fires_on_15_failures_within_10_minutes() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 0.5) for i in range(15)]  # 0 .. 7 minutes
    alerts = detect(events)
    assert rules_fired(alerts) == {"bruteforce"}
    assert alerts[0].severity is Severity.HIGH


def test_bruteforce_does_not_fire_on_14_failures() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 0.5) for i in range(14)]
    assert detect(events) == []


def test_bruteforce_does_not_fire_when_failures_spread_beyond_10_minutes() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 1.5) for i in range(15)]  # 0 .. 21 minutes
    assert "bruteforce" not in rules_fired(detect(events))


def test_bruteforce_does_not_count_failures_from_different_ips() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 0.5, ip=f"10.1.1.{i}") for i in range(20)]
    assert "bruteforce" not in rules_fired(detect(events))


# --- password spraying: 10 or more accounts failing from one IP within 120 minutes, <=2 each ---


def test_spraying_fires_on_10_accounts_from_one_ip() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 5, account=f"acct-{i:02d}", ip="10.9.9.9") for i in range(10)]
    alerts = detect(events)
    assert rules_fired(alerts) == {"password_spraying"}
    assert alerts[0].severity is Severity.MEDIUM


def test_spraying_does_not_fire_on_9_accounts() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 5, account=f"acct-{i:02d}", ip="10.9.9.9") for i in range(9)]
    assert "password_spraying" not in rules_fired(detect(events))


def test_spraying_does_not_fire_when_one_account_dominates() -> None:
    # Many failures on one account are bruteforce territory, not spraying.
    events = [ev(f"evt-a{i:02d}", minutes=i * 1, account="acct-01", ip="10.9.9.9") for i in range(12)]
    events += [ev(f"evt-b{i:02d}", minutes=i * 5, account=f"acct-{i + 2:02d}", ip="10.9.9.9") for i in range(9)]
    assert "password_spraying" not in rules_fired(detect(events))


# --- impossible travel: successes from two countries for one account, within 60 minutes ---


def test_travel_fires_on_two_countries_within_60_minutes() -> None:
    events = [
        ev("evt-h", minutes=0, outcome=Outcome.SUCCESS, country="AR"),
        ev("evt-f", minutes=30, outcome=Outcome.SUCCESS, country="US", ip="10.2.2.2"),
    ]
    alerts = detect(events)
    assert rules_fired(alerts) == {"impossible_travel"}
    assert alerts[0].severity is Severity.HIGH
    assert set(alerts[0].event_ids) == {"evt-h", "evt-f"}


def test_travel_does_not_fire_after_24_hours() -> None:
    events = [
        ev("evt-h", minutes=0, outcome=Outcome.SUCCESS, country="AR"),
        ev("evt-f", minutes=24 * 60 + 1, outcome=Outcome.SUCCESS, country="US"),
    ]
    assert "impossible_travel" not in rules_fired(detect(events))


def test_travel_ignores_failed_logins_from_another_country() -> None:
    events = [
        ev("evt-h", minutes=0, outcome=Outcome.SUCCESS, country="AR"),
        ev("evt-f", minutes=10, outcome=Outcome.FAILURE, country="US"),
    ]
    assert "impossible_travel" not in rules_fired(detect(events))


def test_travel_does_not_fire_on_same_country_twice() -> None:
    events = [
        ev("evt-1", minutes=0, outcome=Outcome.SUCCESS, country="AR"),
        ev("evt-2", minutes=5, outcome=Outcome.SUCCESS, country="AR", ip="10.3.3.3"),
    ]
    assert "impossible_travel" not in rules_fired(detect(events))


# --- alert contract ---


def test_alert_carries_the_required_fields() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 0.5) for i in range(15)]
    (alert,) = detect(events)
    assert alert.rule_id == "bruteforce"
    assert alert.severity in set(Severity)
    assert len(alert.event_ids) == 15
    assert alert.first_seen <= alert.last_seen
    assert alert.evidence and all(isinstance(item, str) and item for item in alert.evidence)
    assert alert.explanation and "15" in alert.explanation


def test_alert_ids_are_deterministic() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 0.5) for i in range(15)]
    assert [a.alert_id for a in detect(events)] == [a.alert_id for a in detect(events)]


def test_detection_does_not_depend_on_input_order() -> None:
    events = [ev(f"evt-{i:02d}", minutes=i * 0.5) for i in range(15)]
    shuffled = list(events)
    random.Random(3).shuffle(shuffled)
    assert detect(events) == detect(shuffled)


# --- false positives on benign traffic ---


def test_benign_generated_traffic_produces_no_alerts() -> None:
    from login_anomaly.simulation.config import GeneratorConfig
    from login_anomaly.simulation.generator import generate

    config = GeneratorConfig(
        seed=5,
        start_utc=datetime(2026, 1, 1, tzinfo=UTC),
        duration_hours=72,
        n_accounts=200,
        n_events=3000,
    )
    assert detect(list(generate(config).events)) == []


@pytest.mark.parametrize("seed", [21, 22])
def test_every_alert_on_a_mixed_dataset_contains_a_malicious_event(seed: int) -> None:
    # Precision check against the labels, done here in the test only. The detector never sees labels.
    from login_anomaly.simulation.config import GeneratorConfig
    from login_anomaly.simulation.generator import generate_with_truth
    from login_anomaly.simulation.scenarios import ScenarioPlan

    config = GeneratorConfig(
        seed=seed,
        start_utc=datetime(2026, 1, 1, tzinfo=UTC),
        duration_hours=72,
        n_accounts=200,
        n_events=3000,
    )
    plan = ScenarioPlan(bruteforce_campaigns=3, password_spraying_campaigns=2, impossible_travel_campaigns=3, benign_travelers=5)
    dataset = generate_with_truth(config, plan)
    malicious_ids = {e.event_id for e in dataset.events if dataset.ground_truth.label_for(e.event_id).is_malicious}
    for alert in detect(list(dataset.events)):
        assert set(alert.event_ids) & malicious_ids, f"false positive: {alert.alert_id} {alert.rule_id}"
