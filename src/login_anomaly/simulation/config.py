"""Generator configuration, schema-independent. Every field is validated on construction.

Validation rules and why:
- Integer fields reject ``bool``. ``bool`` subclasses ``int`` in Python, so
  ``True`` would otherwise pass silently as ``1``.
- ``start_utc`` must be timezone-aware with a zero UTC offset. A non-UTC value
  is rejected rather than converted, so the config that is hashed is exactly
  the config that was written. This matches ``AuthEvent.timestamp_utc``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

# Signed 64-bit maximum, so the seed fits common RNG and storage types.
MAX_SEED = 2**63 - 1
_UTC_OFFSET = timedelta(0)


@dataclass(frozen=True)
class GeneratorConfig:
    seed: int
    start_utc: datetime
    duration_hours: int
    n_accounts: int
    n_events: int

    def __post_init__(self) -> None:
        _require_int(self.seed, "seed", minimum=0, maximum=MAX_SEED)
        _require_utc(self.start_utc, "start_utc")
        _require_int(self.duration_hours, "duration_hours", minimum=1)
        _require_int(self.n_accounts, "n_accounts", minimum=1)
        _require_int(self.n_events, "n_events", minimum=1)


def _require_int(value: object, name: str, *, minimum: int, maximum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int (bool and other types are rejected)")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {value}")


def _require_utc(value: object, name: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(f"{name} must be a datetime")
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    if value.utcoffset() != _UTC_OFFSET:
        raise ValueError(f"{name} must be UTC (zero offset), not converted implicitly")
