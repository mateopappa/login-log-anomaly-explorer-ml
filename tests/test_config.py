import dataclasses
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from login_anomaly.simulation.config import (
    MAX_ACCOUNTS,
    MAX_DURATION_HOURS,
    MAX_EVENTS,
    MAX_SEED,
    GeneratorConfig,
    validate_seed,
)

UTC = timezone.utc


def make_config(**overrides: Any) -> GeneratorConfig:
    fields: dict[str, Any] = {
        "seed": 42,
        "start_utc": datetime(2026, 1, 1, 0, 0, tzinfo=UTC),
        "duration_hours": 24,
        "n_accounts": 10,
        "n_events": 500,
    }
    fields.update(overrides)
    return GeneratorConfig(**fields)


def test_limits_are_the_approved_values() -> None:
    assert MAX_EVENTS == 200_000
    assert MAX_DURATION_HOURS == 8784
    assert MAX_ACCOUNTS == 1_000_000


def test_valid_config_is_accepted() -> None:
    config = make_config()
    assert config.seed == 42
    assert config.duration_hours == 24
    assert config.n_accounts == 10
    assert config.n_events == 500


def test_config_is_frozen() -> None:
    config = make_config()
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.seed = 7  # type: ignore[misc]


def test_config_field_names_are_exact() -> None:
    names = {f.name for f in dataclasses.fields(GeneratorConfig)}
    assert names == {"seed", "start_utc", "duration_hours", "n_accounts", "n_events"}


def test_seed_accepts_zero_and_signed_64_bit_maximum() -> None:
    assert make_config(seed=0).seed == 0
    assert make_config(seed=MAX_SEED).seed == 2**63 - 1


@pytest.mark.parametrize(("seed", "bound"), [(-1, ">= 0"), (2**63, "<= 9223372036854775807")])
def test_seed_rejects_out_of_range(seed: int, bound: str) -> None:
    with pytest.raises(ValueError, match=f"seed must be {bound}"):
        make_config(seed=seed)


@pytest.mark.parametrize("seed", ["1", 1.0, None, True])
def test_seed_rejects_non_int(seed: Any) -> None:
    with pytest.raises(ValueError, match="seed must be an int"):
        make_config(seed=seed)


def test_validate_seed_accepts_bounds_and_rejects_outside() -> None:
    validate_seed(0)
    validate_seed(MAX_SEED)
    with pytest.raises(ValueError, match="seed"):
        validate_seed(-5)
    with pytest.raises(ValueError, match="seed"):
        validate_seed(MAX_SEED + 1)
    with pytest.raises(ValueError, match="seed must be an int"):
        validate_seed(True)


def test_start_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        make_config(start_utc=datetime(2026, 1, 1, 0, 0))


def test_start_rejects_non_utc_offset_even_for_same_instant() -> None:
    # Same instant as 2026-01-01T00:00Z, but not UTC. Rejected rather than normalized.
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        make_config(start_utc=datetime(2025, 12, 31, 21, 0, tzinfo=timezone(timedelta(hours=-3))))


def test_start_accepts_zero_offset_timezone() -> None:
    config = make_config(start_utc=datetime(2026, 1, 1, tzinfo=timezone(timedelta(0))))
    assert config.start_utc.utcoffset() == timedelta(0)


def test_start_rejects_string() -> None:
    with pytest.raises(ValueError, match="must be a datetime"):
        make_config(start_utc="2026-01-01T00:00:00Z")


def test_window_that_overflows_datetime_is_rejected_with_value_error() -> None:
    # 22:00 on the last representable day plus 2 hours is past datetime.max.
    with pytest.raises(ValueError, match="end of window"):
        make_config(start_utc=datetime(9999, 12, 31, 22, 0, tzinfo=UTC), duration_hours=2)


def test_window_ending_at_last_representable_hour_is_accepted() -> None:
    config = make_config(start_utc=datetime(9999, 12, 31, 22, 0, tzinfo=UTC), duration_hours=1)
    assert config.duration_hours == 1


@pytest.mark.parametrize("hours", [0, -1, True, 1.5, "24", None])
def test_duration_hours_rejects_invalid(hours: Any) -> None:
    with pytest.raises(ValueError, match="duration_hours"):
        make_config(duration_hours=hours)


def test_duration_hours_accepts_maximum_and_rejects_above() -> None:
    assert make_config(duration_hours=MAX_DURATION_HOURS).duration_hours == 8784
    with pytest.raises(ValueError, match="duration_hours must be <= 8784"):
        make_config(duration_hours=MAX_DURATION_HOURS + 1)


@pytest.mark.parametrize("accounts", [0, -3, True, 2.0, "10"])
def test_n_accounts_rejects_invalid(accounts: Any) -> None:
    with pytest.raises(ValueError, match="n_accounts"):
        make_config(n_accounts=accounts)


def test_n_accounts_accepts_maximum_and_rejects_above() -> None:
    assert make_config(n_accounts=MAX_ACCOUNTS).n_accounts == MAX_ACCOUNTS
    with pytest.raises(ValueError, match="n_accounts must be <= 1000000"):
        make_config(n_accounts=MAX_ACCOUNTS + 1)


@pytest.mark.parametrize("events", [0, -1, False, 10.0, "500"])
def test_n_events_rejects_invalid(events: Any) -> None:
    with pytest.raises(ValueError, match="n_events"):
        make_config(n_events=events)


def test_n_events_accepts_maximum_and_rejects_above() -> None:
    assert make_config(n_events=MAX_EVENTS).n_events == 200_000
    with pytest.raises(ValueError, match="n_events must be <= 200000"):
        make_config(n_events=MAX_EVENTS + 1)


@pytest.mark.parametrize(
    "field",
    ["seed", "duration_hours", "n_accounts", "n_events"],
)
def test_bool_is_rejected_for_every_integer_field(field: str) -> None:
    # bool is a subclass of int in Python, so True would otherwise pass as 1.
    with pytest.raises(ValueError, match="must be an int"):
        make_config(**{field: True})
