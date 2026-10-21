import dataclasses
from datetime import datetime, timedelta, timezone
from typing import get_type_hints

import pytest

from login_anomaly.events import ALLOWED_COUNTRY_CODES, SCHEMA_VERSION, AuthEvent, Outcome


def make_event(**overrides: object) -> AuthEvent:
    fields: dict[str, object] = {
        "event_id": "evt-000001",
        "timestamp_utc": datetime(2026, 1, 1, 8, 0, tzinfo=timezone.utc),
        "account_id": "acct-0001",
        "source_ip": "192.0.2.10",
        "outcome": Outcome.SUCCESS,
        "country_code": "AR",
    }
    fields.update(overrides)
    return AuthEvent(**fields)  # type: ignore[arg-type]


def test_outcome_values() -> None:
    assert {o.value for o in Outcome} == {"success", "failure"}


def test_event_is_frozen() -> None:
    event = make_event()
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.account_id = "acct-0002"  # type: ignore[misc]


def test_event_field_names_are_exact() -> None:
    names = {f.name for f in dataclasses.fields(AuthEvent)}
    assert names == {
        "event_id",
        "timestamp_utc",
        "account_id",
        "source_ip",
        "outcome",
        "country_code",
    }


def test_event_has_no_label_fields() -> None:
    forbidden = {"label", "is_malicious", "scenario_type", "campaign_id", "scenario_id"}
    names = {f.name for f in dataclasses.fields(AuthEvent)}
    assert names.isdisjoint(forbidden)


def test_valid_event_is_accepted() -> None:
    event = make_event()
    assert event.account_id == "acct-0001"
    assert event.outcome is Outcome.SUCCESS


def test_accepts_all_synthetic_ip_ranges() -> None:
    for ip in ("10.1.2.3", "192.0.2.1", "198.51.100.7", "203.0.113.200"):
        assert make_event(source_ip=ip).source_ip == ip


def test_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError):
        make_event(timestamp_utc=datetime(2026, 1, 1, 8, 0))


def test_rejects_timestamp_that_is_not_a_datetime() -> None:
    with pytest.raises(ValueError):
        make_event(timestamp_utc="2026-01-01T08:00:00Z")  # type: ignore[arg-type]


def test_accepts_explicit_utc_timestamp() -> None:
    event = make_event(timestamp_utc=datetime(2026, 1, 1, 8, 0, tzinfo=timezone.utc))
    assert event.timestamp_utc.utcoffset() == timedelta(0)


def test_rejects_non_utc_timestamp() -> None:
    offset = timezone(timedelta(hours=-3))
    with pytest.raises(ValueError):
        make_event(timestamp_utc=datetime(2026, 1, 1, 8, 0, tzinfo=offset))


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "172.16.0.1", "2001:db8::1"])
def test_rejects_ip_outside_synthetic_ranges(ip: str) -> None:
    with pytest.raises(ValueError):
        make_event(source_ip=ip)


@pytest.mark.parametrize("ip", ["not-an-ip", "", "999.1.1.1"])
def test_rejects_unparseable_ip(ip: str) -> None:
    with pytest.raises(ValueError):
        make_event(source_ip=ip)


def test_rejects_empty_account_id() -> None:
    with pytest.raises(ValueError):
        make_event(account_id="")


def test_rejects_account_id_longer_than_64() -> None:
    with pytest.raises(ValueError):
        make_event(account_id="a" * 65)


def test_accepts_account_id_of_exactly_64() -> None:
    assert make_event(account_id="a" * 64).account_id == "a" * 64


def test_rejects_empty_event_id() -> None:
    with pytest.raises(ValueError):
        make_event(event_id="")


@pytest.mark.parametrize("code", ["XX", "ar", "USA", ""])
def test_rejects_unknown_country(code: str) -> None:
    with pytest.raises(ValueError):
        make_event(country_code=code)


@pytest.mark.parametrize("code", [["AR"], {"AR"}, 42, None])
def test_rejects_non_string_country_as_value_error(code: object) -> None:
    # Unhashable values must fail with ValueError, not TypeError from the set lookup.
    with pytest.raises(ValueError):
        make_event(country_code=code)


def test_country_allowlist_is_exact() -> None:
    assert ALLOWED_COUNTRY_CODES == frozenset({"AR", "BR", "DE", "JP", "US"})


def test_rejects_non_outcome_value() -> None:
    with pytest.raises(ValueError):
        make_event(outcome="success")


def test_accepts_failure_outcome() -> None:
    assert make_event(outcome=Outcome.FAILURE).outcome is Outcome.FAILURE


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.0",
        "10.255.255.255",
        "192.0.2.0",
        "192.0.2.255",
        "198.51.100.0",
        "198.51.100.255",
        "203.0.113.0",
        "203.0.113.255",
    ],
)
def test_accepts_synthetic_range_boundaries(ip: str) -> None:
    assert make_event(source_ip=ip).source_ip == ip


@pytest.mark.parametrize(
    "ip",
    ["9.255.255.255", "11.0.0.0", "192.0.1.255", "192.0.3.0", "198.51.101.0", "203.0.114.0"],
)
def test_rejects_just_outside_synthetic_range_boundaries(ip: str) -> None:
    with pytest.raises(ValueError):
        make_event(source_ip=ip)


def test_rejects_integer_source_ip() -> None:
    # 3232235777 is 192.168.1.1 as an integer; ipaddress would accept it without the type check.
    with pytest.raises(ValueError):
        make_event(source_ip=3232235777)  # type: ignore[arg-type]


def test_schema_version_is_1_0_0() -> None:
    # Changing the schema requires changing this literal on purpose, with a version bump.
    assert SCHEMA_VERSION == "1.0.0"


def test_schema_field_types_are_exact() -> None:
    assert get_type_hints(AuthEvent) == {
        "event_id": str,
        "timestamp_utc": datetime,
        "account_id": str,
        "source_ip": str,
        "outcome": Outcome,
        "country_code": str,
    }
