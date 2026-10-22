"""Small validation helpers shared by the contract modules. Standard library only.

The error messages are part of the contract: tests match on them, so change
them deliberately.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

# Identifiers (event_id, account_id) are pseudonymous codes, not free text.
# This set keeps them free of whitespace, control characters, and separators
# that break log and report formatting. It is hygiene, not a defense against
# prompt injection: that defense is architectural and lives in the investigator.
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")

_UTC_OFFSET = timedelta(0)


def require_int(value: object, name: str, *, minimum: int, maximum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int (bool and other types are rejected)")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {value}")


def require_utc(value: object, name: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(f"{name} must be a datetime")
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    # A zone can have a zero offset at one instant and a non-zero offset later (DST).
    # Only a fixed zero offset is UTC: its utcoffset() is zero for every argument.
    if value.tzinfo.utcoffset(None) != _UTC_OFFSET or value.utcoffset() != _UTC_OFFSET:
        raise ValueError(f"{name} must be timezone-aware UTC (zero offset), not converted implicitly")


def require_non_empty_str(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")


def require_identifier(value: object, name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{name} must match {IDENTIFIER_PATTERN.pattern} "
            "(letters, digits, '.', '_', '-'; 1 to 64 characters)"
        )
