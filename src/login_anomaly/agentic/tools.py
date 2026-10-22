"""Read-only investigation tools, as documented in docs/agentic-evaluators.md, section 5.

Each tool returns ``(ToolCallRecord, rows)``. The record is the single audit entry for the
call. ``rows`` holds only observable fields. On any error the status is "error" and rows is
empty. The tools read events and the investigation input only, never ground truth.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from login_anomaly.agentic.contracts import OBSERVABLE_FIELDS, InvestigationInput, ToolCallRecord
from login_anomaly.events import ALLOWED_COUNTRY_CODES, AuthEvent
from login_anomaly.validation import require_utc

MAX_EVENTS = 500
MAX_WINDOW = timedelta(days=7)
MAX_HISTORY_LIMIT = 200
# Synthetic region names for the allowlisted countries. They describe the synthetic
# environment only; they are not real geography data.
REGIONS: Mapping[str, str] = {"AR": "South America", "BR": "South America", "DE": "Europe", "JP": "Asia", "US": "North America"}

Row = Mapping[str, Any]
ToolOutcome = tuple[ToolCallRecord, tuple[Row, ...]]


@dataclass(frozen=True)
class ToolContext:
    """What the tools may read: observable events and the one alert under investigation."""

    events: tuple[AuthEvent, ...]
    investigation: InvestigationInput


def _outcome(name: str, arguments: Mapping[str, object], ok: bool, rows: Sequence[Row] = ()) -> ToolOutcome:
    record = ToolCallRecord(
        tool_name=name,
        arguments={key: str(value) for key, value in arguments.items()},
        status="ok" if ok else "error",
    )
    return record, tuple(rows) if ok else ()


def _observable(event: AuthEvent) -> Row:
    row = {
        "event_id": event.event_id,
        "timestamp_utc": event.timestamp_utc.isoformat(),
        "account_id": event.account_id,
        "source_ip": event.source_ip,
        "outcome": event.outcome.value,
        "country_code": event.country_code,
    }
    assert set(row) == set(OBSERVABLE_FIELDS)  # guards against exposing a non-observable field
    return row


def _valid_window(start: object, end: object) -> bool:
    try:
        require_utc(start, "start")
        require_utc(end, "end")
    except ValueError:
        return False
    return start <= end and end - start <= MAX_WINDOW  # type: ignore[operator]


def _in_window(events: Sequence[AuthEvent], start: datetime, end: datetime) -> list[AuthEvent]:
    return sorted((e for e in events if start <= e.timestamp_utc <= end), key=lambda e: (e.timestamp_utc, e.event_id))


def get_account_events(ctx: ToolContext, account_id: str, start: datetime, end: datetime) -> ToolOutcome:
    args = {"account_id": account_id, "start": start, "end": end}
    if not isinstance(account_id, str) or not _valid_window(start, end):
        return _outcome("get_account_events", args, ok=False)
    own = [e for e in ctx.events if e.account_id == account_id]
    if not own:
        return _outcome("get_account_events", args, ok=False)
    window = _in_window(own, start, end)
    if len(window) > MAX_EVENTS:
        return _outcome("get_account_events", args, ok=False)
    return _outcome("get_account_events", args, ok=True, rows=[_observable(e) for e in window])


def get_auth_history(ctx: ToolContext, account_id: str, limit: int) -> ToolOutcome:
    args = {"account_id": account_id, "limit": limit}
    valid_limit = isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= MAX_HISTORY_LIMIT
    own = [e for e in ctx.events if e.account_id == account_id] if isinstance(account_id, str) else []
    if not valid_limit or not own:
        return _outcome("get_auth_history", args, ok=False)
    newest_first = sorted(own, key=lambda e: (e.timestamp_utc, e.event_id), reverse=True)[:limit]
    return _outcome("get_auth_history", args, ok=True, rows=[_observable(e) for e in newest_first])


def get_ip_timeline(ctx: ToolContext, source_ip: str, start: datetime, end: datetime) -> ToolOutcome:
    args = {"source_ip": source_ip, "start": start, "end": end}
    if not isinstance(source_ip, str) or not _valid_window(start, end):
        return _outcome("get_ip_timeline", args, ok=False)
    from_ip = [e for e in ctx.events if e.source_ip == source_ip]
    if not from_ip:
        return _outcome("get_ip_timeline", args, ok=False)
    window = _in_window(from_ip, start, end)
    if len(window) > MAX_EVENTS:
        return _outcome("get_ip_timeline", args, ok=False)
    return _outcome("get_ip_timeline", args, ok=True, rows=[_observable(e) for e in window])


def get_geo_context(ctx: ToolContext, country_code: str) -> ToolOutcome:
    args = {"country_code": country_code}
    if not isinstance(country_code, str) or country_code not in ALLOWED_COUNTRY_CODES:
        return _outcome("get_geo_context", args, ok=False)
    return _outcome("get_geo_context", args, ok=True, rows=[{"country_code": country_code, "region": REGIONS[country_code]}])


def get_alert_evidence(ctx: ToolContext, alert_id: str) -> ToolOutcome:
    args = {"alert_id": alert_id}
    investigated = ctx.investigation
    if alert_id != investigated.alert_id:
        return _outcome("get_alert_evidence", args, ok=False)
    # The observable rows of the alert's own events. Without them an investigator holds only
    # opaque ids and cannot pivot to an account or an IP. Ids missing from the events are
    # simply absent here; the caller compares against ``event_ids`` to detect them.
    named = set(investigated.event_ids)
    own = sorted((e for e in ctx.events if e.event_id in named), key=lambda e: (e.timestamp_utc, e.event_id))
    row = {
        "alert_id": investigated.alert_id,
        "rule_id": investigated.rule_id,
        "severity": investigated.severity,
        "event_ids": investigated.event_ids,
        "first_seen": investigated.first_seen.isoformat(),
        "last_seen": investigated.last_seen.isoformat(),
        "events": tuple(_observable(e) for e in own),
    }
    return _outcome("get_alert_evidence", args, ok=True, rows=[row])


TOOLS = {
    "get_account_events": get_account_events,
    "get_auth_history": get_auth_history,
    "get_ip_timeline": get_ip_timeline,
    "get_geo_context": get_geo_context,
    "get_alert_evidence": get_alert_evidence,
}
