"""Regression tests for defects confirmed in the stabilization review.

Each test name states the property it protects. Tests marked "coverage" pass
on the current code and exist so that a regression in that behavior is caught.
"""

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate, generate_with_truth
from login_anomaly.simulation.ground_truth import GroundTruth, ScenarioLabel, ScenarioType
from login_anomaly.simulation.manifest import DatasetManifest
from login_anomaly.validation import require_utc

UTC = timezone.utc


# --- UTC must be a fixed zero offset, not a zone that is zero only at one instant ---


def test_require_utc_rejects_dst_zone_that_is_zero_only_in_winter() -> None:
    london_winter = datetime(2026, 1, 15, 12, 0, tzinfo=ZoneInfo("Europe/London"))
    assert london_winter.utcoffset() == timedelta(0)
    with pytest.raises(ValueError, match="zero offset"):
        require_utc(london_winter, "start_utc")


def test_require_utc_accepts_fixed_zero_offsets() -> None:
    require_utc(datetime(2026, 1, 1, tzinfo=UTC), "ts")
    require_utc(datetime(2026, 1, 1, tzinfo=timezone(timedelta(0))), "ts")


def test_naive_datetime_message_is_exactly_the_naive_message() -> None:
    # Anchored: the zero-offset message also contains "timezone-aware UTC" as a prefix.
    with pytest.raises(ValueError) as info:
        require_utc(datetime(2026, 1, 1), "ts")
    assert str(info.value) == "ts must be timezone-aware UTC"


# --- Ground truth index must not be replaceable through its attribute ---


def test_ground_truth_index_attribute_cannot_be_replaced() -> None:
    truth = GroundTruth([])
    with pytest.raises(AttributeError):
        truth._by_event_id = {}  # type: ignore[misc]


def test_ground_truth_index_attribute_cannot_be_deleted() -> None:
    truth = GroundTruth([])
    with pytest.raises(AttributeError):
        del truth._by_event_id


# --- Label identifiers follow the same identifier rule as events ---


def test_scenario_label_event_id_must_match_identifier_pattern() -> None:
    with pytest.raises(ValueError, match="must match"):
        ScenarioLabel("evt 1", ScenarioType.BENIGN, None, False)


def test_scenario_label_event_id_accepts_identifier() -> None:
    assert ScenarioLabel("evt-1", ScenarioType.BENIGN, None, False).event_id == "evt-1"


# --- Coverage: behaviors the reviewers found untested. These pass on the current code. ---


def _config(**overrides: object) -> GeneratorConfig:
    fields: dict[str, object] = {
        "seed": 42,
        "start_utc": datetime(2026, 1, 1, tzinfo=UTC),
        "duration_hours": 24,
        "n_accounts": 10,
        "n_events": 200,
    }
    fields.update(overrides)
    return GeneratorConfig(**fields)  # type: ignore[arg-type]


def test_timestamps_reach_every_hour_of_the_window() -> None:
    # Guards against a generator that samples only part of the window.
    config = _config(duration_hours=6, n_events=400)
    buckets = {int((e.timestamp_utc - config.start_utc) // timedelta(hours=1)) for e in generate(config).events}
    assert buckets == set(range(6))


def test_generation_at_last_representable_hour_emits_valid_timestamps() -> None:
    config = _config(start_utc=datetime(9999, 12, 31, 22, 0, tzinfo=UTC), duration_hours=1, n_events=20)
    events = generate(config).events
    assert len(events) == 20
    for event in events:
        assert event.timestamp_utc.utcoffset() == timedelta(0)
        assert event.timestamp_utc < datetime.max.replace(tzinfo=UTC)


def test_account_ids_are_literal_zero_padded() -> None:
    config = _config(n_accounts=15, n_events=300)
    accounts = {e.account_id for e in generate(config).events}
    assert accounts <= {f"acct-{i:02d}" for i in range(1, 16)}
    assert all(re.fullmatch(r"acct-(0[1-9]|1[0-5])", account) for account in accounts)


def test_benign_success_rate_matches_declared_probability() -> None:
    from login_anomaly.simulation.generator import BENIGN_SUCCESS_PROBABILITY

    events = generate(_config(n_events=2000)).events
    fraction = sum(e.outcome is Outcome.SUCCESS for e in events) / len(events)
    assert abs(fraction - BENIGN_SUCCESS_PROBABILITY) < 0.02


def test_duplicate_timestamps_are_ordered_by_event_id() -> None:
    # One hour with 500 events forces timestamp collisions, so the tie-break is exercised.
    events = generate(_config(duration_hours=1, n_events=500)).events
    stamps = [e.timestamp_utc for e in events]
    assert len(set(stamps)) < len(stamps)
    for previous, current in zip(events, events[1:]):
        if previous.timestamp_utc == current.timestamp_utc:
            assert previous.event_id < current.event_id


@pytest.mark.parametrize("ip", ["192.0.2.10\n", " 10.0.0.1", "10.0.0.01"])
def test_ip_with_whitespace_or_leading_zeros_is_rejected(ip: str) -> None:
    with pytest.raises(ValueError):
        AuthEvent("evt-1", datetime(2026, 1, 1, tzinfo=UTC), "acct-1", ip, Outcome.SUCCESS, "AR")


def test_manifest_digest_with_trailing_newline_is_rejected() -> None:
    with pytest.raises(ValueError, match="config_sha256"):
        DatasetManifest(seed=1, schema_version="1.0.0", generator_version="0.1.0", config_sha256="a" * 64 + "\n")


def test_generate_with_truth_and_generate_agree_at_the_window_edge() -> None:
    config = _config(start_utc=datetime(9999, 12, 31, 22, 0, tzinfo=UTC), duration_hours=1, n_events=20)
    assert generate(config).events == generate_with_truth(config).events
