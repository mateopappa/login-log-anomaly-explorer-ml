import dataclasses
import random
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import GeneratedDataset, generate
from login_anomaly.simulation.ground_truth import ScenarioType
from login_anomaly.simulation.manifest import DatasetManifest, build_manifest

UTC = timezone.utc
START = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


def make_config(**overrides: Any) -> GeneratorConfig:
    fields: dict[str, Any] = {
        "seed": 42,
        "start_utc": START,
        "duration_hours": 24,
        "n_accounts": 10,
        "n_events": 200,
    }
    fields.update(overrides)
    return GeneratorConfig(**fields)


def universe(config: GeneratorConfig) -> set[str]:
    width = len(str(config.n_accounts))
    return {f"acct-{i:0{width}d}" for i in range(1, config.n_accounts + 1)}


def test_generate_returns_dataset_with_exact_fields() -> None:
    names = {f.name for f in dataclasses.fields(GeneratedDataset)}
    assert names == {"events", "ground_truth", "manifest"}


@pytest.mark.parametrize(
    ("n_events", "n_accounts"),
    [(1, 1), (3, 10), (10, 3), (500, 20), (200, 200)],
)
def test_event_count_is_exact(n_events: int, n_accounts: int) -> None:
    dataset = generate(make_config(n_events=n_events, n_accounts=n_accounts))
    assert len(dataset.events) == n_events
    assert all(isinstance(event, AuthEvent) for event in dataset.events)


def test_timestamps_are_utc_and_inside_configured_window() -> None:
    config = make_config(duration_hours=6, n_events=400)
    end = config.start_utc + timedelta(hours=config.duration_hours)
    for event in generate(config).events:
        assert event.timestamp_utc.utcoffset() == timedelta(0)
        assert config.start_utc <= event.timestamp_utc < end


def test_event_ids_are_unique() -> None:
    events = generate(make_config(n_events=500)).events
    assert len({event.event_id for event in events}) == len(events)


def test_events_are_in_canonical_order() -> None:
    events = generate(make_config(n_events=500)).events
    keys = [(event.timestamp_utc, event.event_id) for event in events]
    assert keys == sorted(keys)


def test_every_event_references_an_account_from_the_universe() -> None:
    config = make_config(n_accounts=15, n_events=300)
    allowed = universe(config)
    for event in generate(config).events:
        assert event.account_id in allowed


def test_each_account_keeps_one_source_ip_and_one_country() -> None:
    events = generate(make_config(n_accounts=5, n_events=400)).events
    ips: dict[str, set[str]] = {}
    countries: dict[str, set[str]] = {}
    for event in events:
        ips.setdefault(event.account_id, set()).add(event.source_ip)
        countries.setdefault(event.account_id, set()).add(event.country_code)
    assert all(len(values) == 1 for values in ips.values())
    assert all(len(values) == 1 for values in countries.values())


def test_outcomes_are_valid_enum_members() -> None:
    events = generate(make_config(n_events=300)).events
    assert {event.outcome for event in events} <= set(Outcome)


def test_every_event_is_benign_and_not_malicious() -> None:
    dataset = generate(make_config(n_events=300))
    for event in dataset.events:
        label = dataset.ground_truth.label_for(event.event_id)
        assert label.scenario_type is ScenarioType.BENIGN
        assert label.is_malicious is False
        assert label.campaign_id is None


def test_ground_truth_covers_exactly_the_generated_events() -> None:
    dataset = generate(make_config(n_events=250))
    assert len(dataset.ground_truth) == len(dataset.events)
    for event in dataset.events:
        assert event.event_id in dataset.ground_truth


def test_manifest_matches_build_manifest_for_the_config() -> None:
    config = make_config()
    dataset = generate(config)
    assert isinstance(dataset.manifest, DatasetManifest)
    assert dataset.manifest == build_manifest(config)
    assert dataset.manifest.seed == config.seed


def test_fewer_events_than_accounts_is_allowed_and_not_all_accounts_appear() -> None:
    # Contract: n_accounts is the universe; n_events is the exact event count.
    # No requirement that every account appears, so fewer events than accounts is valid.
    config = make_config(n_events=3, n_accounts=10)
    dataset = generate(config)
    assert len(dataset.events) == 3
    seen = {event.account_id for event in dataset.events}
    assert seen <= universe(config)
    assert len(seen) <= 3


def test_single_account_universe_uses_that_account_for_every_event() -> None:
    dataset = generate(make_config(n_accounts=1, n_events=5))
    assert {event.account_id for event in dataset.events} == {"acct-1"}


def test_generate_does_not_touch_the_global_random_state() -> None:
    random.seed(999)
    before = random.getstate()
    generate(make_config(n_events=100))
    assert random.getstate() == before
