"""SOC Live event sources: deterministic, unique ids, time-ordered, attacks only where configured."""

from datetime import timedelta

import pytest

from login_anomaly.detection.rules import detect
from login_anomaly.live.sources import (
    ATTACK_EVERY_CHUNKS,
    CHUNK_EVENTS,
    CHUNK_HOURS,
    REPLAY_EVENTS,
    REPLAY_SCENARIOS,
    START_UTC,
    ContinuousSource,
    ReplaySource,
    replay_events,
)

ALL_ATTACKS = frozenset({"bruteforce", "password_spraying", "impossible_travel"})


def test_replay_is_deterministic_and_seed_sensitive() -> None:
    first = replay_events("Mixed campaigns", 31)
    assert first == replay_events("Mixed campaigns", 31)
    assert first != replay_events("Mixed campaigns", 32)
    assert len(first) == REPLAY_EVENTS
    assert len({e.event_id for e in first}) == REPLAY_EVENTS
    assert list(first) == sorted(first, key=lambda e: (e.timestamp_utc, e.event_id))


def test_unknown_replay_scenario_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown replay scenario"):
        replay_events("No such scenario", 1)


def test_replay_source_releases_in_order_and_reports_pending() -> None:
    events = replay_events("Benign only", 5)
    source = ReplaySource(events)
    assert source.generated() == REPLAY_EVENTS and source.pending() == REPLAY_EVENTS
    first = source.take(3)
    assert first == events[:3] and source.pending() == REPLAY_EVENTS - 3
    rest = source.take(10**6)
    assert rest == events[3:] and source.pending() == 0 and source.take(5) == ()


def test_continuous_chunks_are_deterministic_and_unique() -> None:
    first = ContinuousSource(7, ALL_ATTACKS).take(5 * CHUNK_EVENTS)
    assert first == ContinuousSource(7, ALL_ATTACKS).take(5 * CHUNK_EVENTS)
    assert len({e.event_id for e in first}) == len(first)  # chunk namespacing prevents collisions
    assert len({e.account_id for e in first}) > CHUNK_EVENTS // 10


def test_continuous_chunks_advance_in_time_without_overlap() -> None:
    source = ContinuousSource(7, ALL_ATTACKS)
    events = source.take(4 * CHUNK_EVENTS)
    assert list(events) == sorted(events, key=lambda e: (e.timestamp_utc, e.event_id))
    for index in range(4):
        chunk_start = START_UTC + timedelta(hours=CHUNK_HOURS * index)
        window = events[index * CHUNK_EVENTS : (index + 1) * CHUNK_EVENTS]
        assert all(chunk_start <= e.timestamp_utc < chunk_start + timedelta(hours=CHUNK_HOURS) for e in window)


def test_continuous_source_reports_generated_and_pending() -> None:
    source = ContinuousSource(7, frozenset())
    assert source.generated() == 0 and source.pending() == 0
    source.take(10)
    assert source.generated() == CHUNK_EVENTS and source.pending() == CHUNK_EVENTS - 10


def test_attacks_appear_only_in_attack_chunks_and_are_detected() -> None:
    attack_chunk = ATTACK_EVERY_CHUNKS - 1  # the first chunk that receives campaigns
    events = ContinuousSource(7, ALL_ATTACKS).take((attack_chunk + 1) * CHUNK_EVENTS)
    window = events[attack_chunk * CHUNK_EVENTS :]
    assert detect(window), "campaign chunk should trigger at least one rule through the real detector"
    benign_only = ContinuousSource(7, frozenset()).take((attack_chunk + 1) * CHUNK_EVENTS)
    assert detect(benign_only[attack_chunk * CHUNK_EVENTS :]) == []


def test_different_seeds_give_different_streams() -> None:
    assert ContinuousSource(1, ALL_ATTACKS).take(20) != ContinuousSource(2, ALL_ATTACKS).take(20)


def test_replay_scenario_names_are_stable() -> None:
    assert set(REPLAY_SCENARIOS) == {"Mixed campaigns", "Bruteforce only", "Password spraying only", "Benign only"}
