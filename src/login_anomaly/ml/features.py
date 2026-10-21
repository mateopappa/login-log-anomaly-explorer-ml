"""Causal event features for the ML baseline.

Every feature for an event uses only that event and earlier events. Later events
never change an earlier row. Identifiers (event_id, account_id, source_ip) are used
to group events, but they are not features. Labels never enter this module.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from datetime import datetime, timedelta

from login_anomaly.events import AuthEvent, Outcome

FEATURE_NAMES: tuple[str, ...] = (
    "is_failure",
    "failures_acct_ip_10min",
    "failures_ip_120min",
    "distinct_accounts_failed_ip_120min",
    "minutes_since_prev_event_same_account",
    "country_changed_since_previous",
    "is_home_country",
    "ip_new_for_account",
)

_CAP_MINUTES = 1440.0
_TEN_MIN = timedelta(minutes=10)
_TWO_HOURS = timedelta(minutes=120)


def feature_matrix(events: Iterable[AuthEvent]) -> tuple[list[str], list[list[float]]]:
    """Return event ids and one feature row per event, in canonical event order."""
    ordered = sorted(events, key=lambda event: (event.timestamp_utc, event.event_id))

    acct_ip_failures: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    ip_failures: dict[str, deque[datetime]] = defaultdict(deque)
    ip_accounts: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
    ip_counts: dict[str, Counter[str]] = defaultdict(Counter)
    last_event: dict[str, AuthEvent] = {}
    country_counts: dict[str, Counter[str]] = defaultdict(Counter)
    ips_seen: dict[str, set[str]] = defaultdict(set)

    ids: list[str] = []
    rows: list[list[float]] = []
    for event in ordered:
        now = event.timestamp_utc
        is_failure = 1.0 if event.outcome is Outcome.FAILURE else 0.0

        if is_failure:
            acct_ip_failures[(event.account_id, event.source_ip)].append(now)
            ip_failures[event.source_ip].append(now)
            ip_accounts[event.source_ip].append((now, event.account_id))
            ip_counts[event.source_ip][event.account_id] += 1
        _prune(acct_ip_failures[(event.account_id, event.source_ip)], now, _TEN_MIN)
        _prune(ip_failures[event.source_ip], now, _TWO_HOURS)
        _prune_accounts(ip_accounts[event.source_ip], ip_counts[event.source_ip], now, _TWO_HOURS)

        previous = last_event.get(event.account_id)
        if previous is None:
            gap_minutes = _CAP_MINUTES
            country_changed = 0.0
        else:
            gap_minutes = min((now - previous.timestamp_utc).total_seconds() / 60.0, _CAP_MINUTES)
            country_changed = 1.0 if previous.country_code != event.country_code else 0.0

        counts = country_counts[event.account_id]
        if counts:
            home = max(sorted(counts), key=lambda country: counts[country])
            is_home = 1.0 if event.country_code == home else 0.0
        else:
            is_home = 1.0
        counts[event.country_code] += 1

        ip_new = 0.0 if event.source_ip in ips_seen[event.account_id] else 1.0
        ips_seen[event.account_id].add(event.source_ip)
        last_event[event.account_id] = event

        ids.append(event.event_id)
        rows.append(
            [
                is_failure,
                float(len(acct_ip_failures[(event.account_id, event.source_ip)])),
                float(len(ip_failures[event.source_ip])),
                float(len(ip_counts[event.source_ip])),
                gap_minutes,
                country_changed,
                is_home,
                ip_new,
            ]
        )
    return ids, rows


def _prune(stamps: deque[datetime], now: datetime, horizon: timedelta) -> None:
    while stamps and now - stamps[0] > horizon:
        stamps.popleft()


def _prune_accounts(
    entries: deque[tuple[datetime, str]], counts: Counter[str], now: datetime, horizon: timedelta
) -> None:
    while entries and now - entries[0][0] > horizon:
        _, account = entries.popleft()
        counts[account] -= 1
        if counts[account] <= 0:
            del counts[account]
