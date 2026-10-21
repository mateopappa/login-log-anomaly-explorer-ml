"""Rule-based detector. Independent of the ML detector; no score aggregation between them.

Input: ``AuthEvent`` objects only. The detector never receives labels, campaign ids,
or scenario types, and it does not import the simulation package.

Rules (thresholds are module constants, so they are easy to read and to test):

- ``bruteforce``: 15 or more failures on one account from one source IP within 10 minutes.
- ``password_spraying``: 10 or more distinct accounts, each with 1 or 2 failures,
  from one source IP within 120 minutes.
- ``impossible_travel``: two consecutive successful logins on one account from
  different countries, 60 minutes or less apart.

Each alert names the events it is based on, the evidence in text form, and a
one-sentence explanation of the threshold that fired.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum

from login_anomaly.events import AuthEvent, Outcome

BRUTEFORCE_MIN_FAILURES = 15
BRUTEFORCE_WINDOW = timedelta(minutes=10)
SPRAYING_MIN_ACCOUNTS = 10
SPRAYING_MAX_FAILURES_PER_ACCOUNT = 2
SPRAYING_WINDOW = timedelta(minutes=120)
TRAVEL_MAX_GAP = timedelta(minutes=60)


class Severity(Enum):
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule_id: str
    severity: Severity
    event_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    evidence: tuple[str, ...]
    explanation: str


def detect(events: Iterable[AuthEvent]) -> list[Alert]:
    """Run every rule over the events. Output order and alert ids do not depend on input order."""
    ordered = sorted(events, key=lambda event: (event.timestamp_utc, event.event_id))
    alerts = [*_bruteforce(ordered), *_spraying(ordered), *_travel(ordered)]
    alerts.sort(key=lambda alert: (alert.first_seen, alert.rule_id, alert.event_ids))
    return [replace(alert, alert_id=f"alt-{index:04d}") for index, alert in enumerate(alerts, start=1)]


def _failures(events: list[AuthEvent]) -> list[AuthEvent]:
    return [event for event in events if event.outcome is Outcome.FAILURE]


def _bruteforce(events: list[AuthEvent]) -> list[Alert]:
    groups: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in _failures(events):
        groups[(event.account_id, event.source_ip)].append(event)

    alerts: list[Alert] = []
    for (account, source), group in groups.items():
        best: list[AuthEvent] = []
        left = 0
        for right in range(len(group)):
            while group[right].timestamp_utc - group[left].timestamp_utc > BRUTEFORCE_WINDOW:
                left += 1
            if right - left + 1 > len(best):
                best = group[left : right + 1]
        if len(best) >= BRUTEFORCE_MIN_FAILURES:
            first, last = best[0].timestamp_utc, best[-1].timestamp_utc
            alerts.append(
                Alert(
                    alert_id="",
                    rule_id="bruteforce",
                    severity=Severity.HIGH,
                    event_ids=tuple(event.event_id for event in best),
                    first_seen=first,
                    last_seen=last,
                    evidence=(
                        f"{len(best)} failed logins for {account} from {source} "
                        f"between {first.isoformat()} and {last.isoformat()}",
                    ),
                    explanation=(
                        f"{len(best)} failures on one account from one source within "
                        f"{int(BRUTEFORCE_WINDOW.total_seconds() // 60)} minutes; threshold is {BRUTEFORCE_MIN_FAILURES}."
                    ),
                )
            )
    return alerts


def _spraying(events: list[AuthEvent]) -> list[Alert]:
    by_source: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in _failures(events):
        by_source[event.source_ip].append(event)

    alerts: list[Alert] = []
    for source, group in by_source.items():
        best: list[AuthEvent] = []
        best_accounts = 0
        left = 0
        for right in range(len(group)):
            while group[right].timestamp_utc - group[left].timestamp_utc > SPRAYING_WINDOW:
                left += 1
            window = group[left : right + 1]
            per_account: dict[str, list[AuthEvent]] = defaultdict(list)
            for event in window:
                per_account[event.account_id].append(event)
            eligible = {account: items for account, items in per_account.items() if len(items) <= SPRAYING_MAX_FAILURES_PER_ACCOUNT}
            if len(eligible) > best_accounts:
                best_accounts = len(eligible)
                best = sorted((event for items in eligible.values() for event in items), key=lambda e: (e.timestamp_utc, e.event_id))
        if best_accounts >= SPRAYING_MIN_ACCOUNTS:
            first, last = best[0].timestamp_utc, best[-1].timestamp_utc
            alerts.append(
                Alert(
                    alert_id="",
                    rule_id="password_spraying",
                    severity=Severity.MEDIUM,
                    event_ids=tuple(event.event_id for event in best),
                    first_seen=first,
                    last_seen=last,
                    evidence=(
                        f"{best_accounts} accounts with 1 to {SPRAYING_MAX_FAILURES_PER_ACCOUNT} failures each "
                        f"from {source} between {first.isoformat()} and {last.isoformat()}",
                    ),
                    explanation=(
                        f"One source failed against {best_accounts} distinct accounts within "
                        f"{int(SPRAYING_WINDOW.total_seconds() // 60)} minutes with few attempts per account; "
                        f"threshold is {SPRAYING_MIN_ACCOUNTS}."
                    ),
                )
            )
    return alerts


def _travel(events: list[AuthEvent]) -> list[Alert]:
    by_account: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.outcome is Outcome.SUCCESS:
            by_account[event.account_id].append(event)

    alerts: list[Alert] = []
    for account, group in by_account.items():
        for previous, current in zip(group, group[1:]):
            gap = current.timestamp_utc - previous.timestamp_utc
            if previous.country_code == current.country_code:
                continue
            if not timedelta(0) < gap <= TRAVEL_MAX_GAP:
                continue
            alerts.append(
                Alert(
                    alert_id="",
                    rule_id="impossible_travel",
                    severity=Severity.HIGH,
                    event_ids=(previous.event_id, current.event_id),
                    first_seen=previous.timestamp_utc,
                    last_seen=current.timestamp_utc,
                    evidence=(
                        f"{account} logged in from {previous.country_code} at {previous.timestamp_utc.isoformat()} "
                        f"and from {current.country_code} at {current.timestamp_utc.isoformat()}",
                    ),
                    explanation=(
                        f"Successful logins from two countries {int(gap.total_seconds() // 60)} minutes apart; "
                        f"threshold is {int(TRAVEL_MAX_GAP.total_seconds() // 60)} minutes."
                    ),
                )
            )
    return alerts
