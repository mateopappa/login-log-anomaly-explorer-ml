"""Observable authentication event contract, schema version 1.0.0.

Only fields a detector or investigator may see belong here. Ground-truth
labels live in ``login_anomaly.simulation`` and must not be imported by
detection or investigation code.

``country_code`` is contextual. A country change alone is never sufficient to
classify an event as malicious; detectors must combine it with timing and
with other events for the same account.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from login_anomaly.validation import require_identifier, require_utc

SCHEMA_VERSION = "1.0.0"
ALLOWED_COUNTRY_CODES: frozenset[str] = frozenset({"AR", "BR", "DE", "JP", "US"})

# Only addresses from these networks may appear in events. None of them is a
# real client address, so generated data cannot be mistaken for real traffic.
SYNTHETIC_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    # RFC 1918 private space. Stands in for internal or VPN-side sources.
    ipaddress.IPv4Network("10.0.0.0/8"),
    # RFC 5737 TEST-NET-1, reserved for documentation and examples.
    ipaddress.IPv4Network("192.0.2.0/24"),
    # RFC 5737 TEST-NET-2, reserved for documentation and examples.
    ipaddress.IPv4Network("198.51.100.0/24"),
    # RFC 5737 TEST-NET-3, reserved for documentation and examples.
    ipaddress.IPv4Network("203.0.113.0/24"),
)


class Outcome(Enum):
    SUCCESS = "success"
    FAILURE = "failure"


@dataclass(frozen=True)
class AuthEvent:
    """One login attempt as a detector sees it.

    Validation runs in ``__post_init__``, so an invalid event cannot exist.
    The generator, ingestion, and tests all build events through this
    constructor, which keeps a single validation rule and avoids a second,
    separate function that could drift from it.

    ``event_id`` and ``account_id`` are identifiers: see ``IDENTIFIER_PATTERN``.
    """

    event_id: str
    timestamp_utc: datetime
    account_id: str
    source_ip: str
    outcome: Outcome
    country_code: str

    def __post_init__(self) -> None:
        require_identifier(self.event_id, "event_id")
        require_utc(self.timestamp_utc, "timestamp_utc")
        require_identifier(self.account_id, "account_id")
        _require_synthetic_ipv4(self.source_ip)
        if not isinstance(self.outcome, Outcome):
            raise ValueError("outcome must be an Outcome member")
        _require_country_code(self.country_code)


def _require_country_code(country_code: object) -> None:
    # Check the type first: a list or dict would raise TypeError on the set lookup.
    if not isinstance(country_code, str) or country_code not in ALLOWED_COUNTRY_CODES:
        raise ValueError(f"country_code not allowed: {country_code!r}")


def _require_synthetic_ipv4(source_ip: object) -> None:
    if not isinstance(source_ip, str):
        raise ValueError("source_ip must be a string")
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ValueError(f"source_ip is not an IP address: {source_ip!r}") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("source_ip must be IPv4")
    if not any(address in network for network in SYNTHETIC_IPV4_NETWORKS):
        raise ValueError(f"source_ip is outside synthetic ranges: {source_ip}")
