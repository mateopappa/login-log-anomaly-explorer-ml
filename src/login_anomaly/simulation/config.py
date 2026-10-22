"""Generator configuration, schema-independent. Every field is validated on construction.

Validation rules and why:
- Integer fields reject ``bool``. ``bool`` subclasses ``int`` in Python, so
  ``True`` would otherwise pass silently as ``1``.
- ``start_utc`` must be timezone-aware with a zero UTC offset. A non-UTC value
  is rejected rather than converted, so the config that is hashed is exactly
  the config that was written. This matches ``AuthEvent.timestamp_utc``.
- Upper bounds protect the generator from configurations that exhaust memory
  or time. They are protection limits, not volumes validated by load tests.
  ``MAX_EVENTS`` is set for the in-memory generator and should be revisited
  when persistence or streaming exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from login_anomaly.validation import require_int, require_utc

# Signed 64-bit maximum, so the seed fits common RNG and storage types.
MAX_SEED = 2**63 - 1
# Protection limit for the in-memory generator. Not a validated throughput figure.
MAX_EVENTS = 200_000
# Protection limit. The generator creates one profile per account.
MAX_ACCOUNTS = 1_000_000
# One calendar year, including a leap day. Scenario windows are minutes to hours.
MAX_DURATION_HOURS = 8784


def validate_seed(value: object) -> None:
    require_int(value, "seed", minimum=0, maximum=MAX_SEED)


@dataclass(frozen=True)
class GeneratorConfig:
    seed: int
    start_utc: datetime
    duration_hours: int
    n_accounts: int
    n_events: int

    def __post_init__(self) -> None:
        validate_seed(self.seed)
        require_utc(self.start_utc, "start_utc")
        require_int(self.duration_hours, "duration_hours", minimum=1, maximum=MAX_DURATION_HOURS)
        require_int(self.n_accounts, "n_accounts", minimum=1, maximum=MAX_ACCOUNTS)
        require_int(self.n_events, "n_events", minimum=1, maximum=MAX_EVENTS)
        _require_window_fits(self.start_utc, self.duration_hours)


def _require_window_fits(start_utc: datetime, duration_hours: int) -> None:
    # The window end must be representable, or generation would fail with OverflowError.
    try:
        start_utc + timedelta(hours=duration_hours)
    except OverflowError as exc:
        raise ValueError("end of window (start_utc + duration_hours) exceeds the datetime range") from exc
