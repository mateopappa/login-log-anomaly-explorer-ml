"""Malicious scenarios: signatures, label integrity, exact budget, reproducibility, failure modes.

Signatures are checked from events alone, the way a detector sees them. Labels are
checked against the events they describe.
"""

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import pytest

from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate, generate_with_truth
from login_anomaly.simulation.ground_truth import ScenarioType
from login_anomaly.simulation.scenarios import ScenarioPlan

UTC = timezone.utc
POOL = ipaddress.IPv4Network("10.0.0.0/8")


def config(**overrides: object) -> GeneratorConfig:
    fields: dict[str, object] = {
        "seed": 11,
        "start_utc": datetime(2026, 1, 1, tzinfo=UTC),
        # 72 hours: benign travelers need a gap of at least 24 hours inside the window.
        "duration_hours": 72,
        "n_accounts": 200,
        "n_events": 3000,
    }
    fields.update(overrides)
    return GeneratorConfig(**fields)  # type: ignore[arg-type]


PLAN = ScenarioPlan(
    bruteforce_campaigns=4,
    password_spraying_campaigns=2,
    impossible_travel_campaigns=4,
    benign_travelers=5,
)


@pytest.fixture(scope="module")
def dataset():
    return generate_with_truth(config(), PLAN)


def _campaign_events(dataset, campaign_id: str) -> list[AuthEvent]:
    return [
        e
        for e in dataset.events
        if dataset.ground_truth.label_for(e.event_id).campaign_id == campaign_id
    ]


# --- plan validation ---


def test_scenario_plan_defaults_to_empty() -> None:
    assert ScenarioPlan().is_empty()
    assert not PLAN.is_empty()


@pytest.mark.parametrize("field", ["bruteforce_campaigns", "password_spraying_campaigns", "impossible_travel_campaigns", "benign_travelers"])
@pytest.mark.parametrize("value", [-1, True, 1.0, "2"])
def test_scenario_plan_rejects_invalid_counts(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=field):
        ScenarioPlan(**{field: value})  # type: ignore[arg-type]


# --- budget and feasibility ---


def test_total_events_are_exact_including_malicious() -> None:
    assert len(generate(config(), PLAN).events) == 3000
    assert len(generate_with_truth(config(), PLAN).events) == 3000


def test_plan_that_does_not_fit_n_events_is_rejected_clearly() -> None:
    with pytest.raises(ValueError, match="n_events"):
        generate(config(n_events=20), PLAN)


def test_spraying_needs_enough_accounts() -> None:
    with pytest.raises(ValueError, match="accounts"):
        generate(config(n_accounts=5, n_events=3000), ScenarioPlan(password_spraying_campaigns=1))


def test_window_too_short_for_scenarios_is_rejected() -> None:
    with pytest.raises(ValueError, match="window"):
        generate(config(duration_hours=1), ScenarioPlan(password_spraying_campaigns=1))


# --- labels: counts and integrity ---


def test_malicious_label_count_matches_scenario_events(dataset) -> None:
    malicious = [e for e in dataset.events if dataset.ground_truth.label_for(e.event_id).is_malicious]
    assert len(malicious) > 0
    for event in malicious:
        label = dataset.ground_truth.label_for(event.event_id)
        assert label.campaign_id is not None
        assert label.scenario_type is not ScenarioType.BENIGN


def test_each_campaign_has_one_scenario_type(dataset) -> None:
    types: dict[str, set[ScenarioType]] = defaultdict(set)
    for event in dataset.events:
        label = dataset.ground_truth.label_for(event.event_id)
        if label.campaign_id is not None:
            types[label.campaign_id].add(label.scenario_type)
    assert all(len(kinds) == 1 for kinds in types.values())


def test_benign_events_carry_no_campaign(dataset) -> None:
    for event in dataset.events:
        label = dataset.ground_truth.label_for(event.event_id)
        if label.scenario_type is ScenarioType.BENIGN:
            assert label.campaign_id is None
            assert label.is_malicious is False


def test_campaign_counts_match_the_plan(dataset) -> None:
    by_type: dict[ScenarioType, set[str]] = defaultdict(set)
    for event in dataset.events:
        label = dataset.ground_truth.label_for(event.event_id)
        if label.campaign_id is not None:
            by_type[label.scenario_type].add(label.campaign_id)
    assert len(by_type[ScenarioType.BRUTEFORCE]) == 4
    assert len(by_type[ScenarioType.PASSWORD_SPRAYING]) == 2
    assert len(by_type[ScenarioType.IMPOSSIBLE_TRAVEL]) == 4


# --- observable signatures, checked from events only ---


def test_bruteforce_signature(dataset) -> None:
    for campaign_id in {c for c in _campaign_ids(dataset, ScenarioType.BRUTEFORCE)}:
        events = _campaign_events(dataset, campaign_id)
        assert len({e.account_id for e in events}) == 1
        assert len({e.source_ip for e in events}) == 1
        failures = [e for e in events if e.outcome is Outcome.FAILURE]
        assert 15 <= len(failures) <= 40
        span = max(e.timestamp_utc for e in events) - min(e.timestamp_utc for e in events)
        assert span <= timedelta(minutes=10)


def test_password_spraying_signature(dataset) -> None:
    for campaign_id in _campaign_ids(dataset, ScenarioType.PASSWORD_SPRAYING):
        events = _campaign_events(dataset, campaign_id)
        assert len({e.source_ip for e in events}) == 1
        accounts = defaultdict(int)
        for e in events:
            accounts[e.account_id] += 1
        assert 10 <= len(accounts) <= 25
        assert all(1 <= count <= 2 for count in accounts.values())
        assert all(e.outcome is Outcome.FAILURE for e in events)
        span = max(e.timestamp_utc for e in events) - min(e.timestamp_utc for e in events)
        assert span <= timedelta(minutes=120)


def test_impossible_travel_signature(dataset) -> None:
    for campaign_id in _campaign_ids(dataset, ScenarioType.IMPOSSIBLE_TRAVEL):
        malicious = [e for e in _campaign_events(dataset, campaign_id)]
        assert len(malicious) == 1
        attack = malicious[0]
        assert attack.outcome is Outcome.SUCCESS
        # The victim's home-country login sits shortly before the foreign one.
        home = [
            e
            for e in dataset.events
            if e.account_id == attack.account_id
            and e.country_code != attack.country_code
            and timedelta(0) < attack.timestamp_utc - e.timestamp_utc <= timedelta(minutes=60)
        ]
        assert home, "no home-country login within 60 minutes before the foreign login"
        assert all(dataset.ground_truth.label_for(e.event_id).is_malicious is False for e in home)


def _campaign_ids(dataset, scenario_type: ScenarioType) -> set[str]:
    return {
        dataset.ground_truth.label_for(e.event_id).campaign_id
        for e in dataset.events
        if dataset.ground_truth.label_for(e.event_id).scenario_type is scenario_type
    }


# --- negatives: benign traffic must not match the signatures ---


def test_benign_travelers_switch_country_with_a_long_gap(dataset) -> None:
    travelers = defaultdict(list)
    for e in dataset.events:
        label = dataset.ground_truth.label_for(e.event_id)
        if label.scenario_type is ScenarioType.BENIGN:
            travelers[e.account_id].append(e)
    legit_changes = []
    for account_events in travelers.values():
        ordered = sorted(account_events, key=lambda e: e.timestamp_utc)
        for previous, current in zip(ordered, ordered[1:]):
            if previous.country_code != current.country_code:
                legit_changes.append(current.timestamp_utc - previous.timestamp_utc)
    assert len(legit_changes) >= 5
    assert all(gap >= timedelta(hours=24) for gap in legit_changes)


def test_benign_only_dataset_has_no_malicious_labels() -> None:
    dataset = generate_with_truth(config(n_events=500))
    assert not any(dataset.ground_truth.label_for(e.event_id).is_malicious for e in dataset.events)


def test_no_benign_account_matches_the_bruteforce_signature(dataset) -> None:
    per_account_ip = defaultdict(int)
    benign_ids = {
        e.event_id
        for e in dataset.events
        if dataset.ground_truth.label_for(e.event_id).scenario_type is ScenarioType.BENIGN
    }
    for e in dataset.events:
        if e.event_id in benign_ids and e.outcome is Outcome.FAILURE:
            per_account_ip[(e.account_id, e.source_ip)] += 1
    assert max(per_account_ip.values(), default=0) < 15


# --- ids and sources ---


def test_campaign_event_ids_are_not_contiguous(dataset) -> None:
    numbers = sorted(
        int(e.event_id.split("-")[1])
        for e in dataset.events
        if dataset.ground_truth.label_for(e.event_id).is_malicious
    )
    gaps = [b - a for a, b in zip(numbers, numbers[1:])]
    assert max(gaps) > 1


def test_attacker_sources_come_from_the_same_pool_as_benign_sources(dataset) -> None:
    for e in dataset.events:
        assert ipaddress.IPv4Address(e.source_ip) in POOL


# --- reproducibility ---


def test_same_config_and_plan_give_identical_rows() -> None:
    a = generate_with_truth(config(n_events=800), PLAN)
    b = generate_with_truth(config(n_events=800), PLAN)
    assert a.events == b.events
    assert all(
        a.ground_truth.label_for(e.event_id) == b.ground_truth.label_for(e.event_id) for e in a.events
    )


def test_different_plans_give_different_datasets() -> None:
    a = generate(config(n_events=800), PLAN)
    b = generate(config(n_events=800), ScenarioPlan(bruteforce_campaigns=1))
    assert a.events != b.events
