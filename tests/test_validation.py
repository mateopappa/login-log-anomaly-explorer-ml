from datetime import datetime, timedelta, timezone

import pytest

from login_anomaly.validation import (
    IDENTIFIER_PATTERN,
    require_identifier,
    require_int,
    require_non_empty_str,
    require_utc,
)


def test_require_int_accepts_bounds() -> None:
    require_int(0, "x", minimum=0)
    require_int(5, "x", minimum=0, maximum=5)


@pytest.mark.parametrize("value", [True, False, 1.0, "1", None])
def test_require_int_rejects_non_int_including_bool(value: object) -> None:
    with pytest.raises(ValueError, match="must be an int"):
        require_int(value, "x", minimum=0)


def test_require_int_rejects_below_minimum() -> None:
    with pytest.raises(ValueError, match="must be >= 1"):
        require_int(0, "x", minimum=1)


def test_require_int_rejects_above_maximum() -> None:
    with pytest.raises(ValueError, match="must be <= 5"):
        require_int(6, "x", minimum=0, maximum=5)


def test_require_utc_accepts_zero_offset() -> None:
    require_utc(datetime(2026, 1, 1, tzinfo=timezone.utc), "ts")


def test_require_utc_rejects_naive() -> None:
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        require_utc(datetime(2026, 1, 1), "ts")


def test_require_utc_rejects_non_zero_offset_for_same_instant() -> None:
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        require_utc(datetime(2025, 12, 31, 21, tzinfo=timezone(timedelta(hours=-3))), "ts")


def test_require_utc_rejects_non_datetime() -> None:
    with pytest.raises(ValueError, match="must be a datetime"):
        require_utc("2026-01-01T00:00:00Z", "ts")


def test_require_non_empty_str_accepts_text() -> None:
    require_non_empty_str("a", "x")


@pytest.mark.parametrize("value", ["", None, 3])
def test_require_non_empty_str_rejects_invalid(value: object) -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        require_non_empty_str(value, "x")


@pytest.mark.parametrize("value", ["evt-000001", "acct_1.A-9", "a" * 64])
def test_require_identifier_accepts_allowed_characters(value: str) -> None:
    require_identifier(value, "x")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 65,
        "a b",
        "a\nb",
        "a\n",
        "\t",
        "é",
        "a/b",
        "ignore previous instructions",
    ],
)
def test_require_identifier_rejects_disallowed_text(value: str) -> None:
    with pytest.raises(ValueError, match="must match"):
        require_identifier(value, "x")


@pytest.mark.parametrize("value", [None, 7, ["x"]])
def test_require_identifier_rejects_non_string_with_clear_message(value: object) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        require_identifier(value, "x")


def test_identifier_pattern_is_the_approved_one() -> None:
    assert IDENTIFIER_PATTERN.pattern == r"[A-Za-z0-9._-]{1,64}"
