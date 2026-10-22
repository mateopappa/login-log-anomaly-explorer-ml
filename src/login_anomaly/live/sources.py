"""Event sources for SOC Live. They release ``AuthEvent`` objects only, never labels.

Replay: one fixed scenario is generated up front by the existing generator and released in order.

Continuous: deterministic chunks of 3 hours, each generated independently by the existing generator
and namespaced so that event and account ids never collide across chunks. Accounts and IP histories
do not carry over between chunks. Campaigns stay inside their chunk, so they are never split.
"""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from login_anomaly.events import AuthEvent
from login_anomaly.simulation.config import MAX_SEED, GeneratorConfig
from login_anomaly.simulation.generator import generate
from login_anomaly.simulation.scenarios import ScenarioPlan

START_UTC = datetime(2026, 1, 1, tzinfo=timezone.utc)
ATTACK_FAMILIES: tuple[str, ...] = ("bruteforce", "password_spraying", "impossible_travel")

REPLAY_EVENTS = 1500
REPLAY_ACCOUNTS = 150
REPLAY_HOURS = 72
REPLAY_SCENARIOS: dict[str, ScenarioPlan] = {
    "Mixed campaigns": ScenarioPlan(bruteforce_campaigns=2, password_spraying_campaigns=1, impossible_travel_campaigns=2, benign_travelers=2),
    "Bruteforce only": ScenarioPlan(bruteforce_campaigns=2),
    "Password spraying only": ScenarioPlan(password_spraying_campaigns=1),
    "Benign only": ScenarioPlan(),
}

# Spraying and travel windows need 2 hours, so a chunk spans 3 hours.
CHUNK_EVENTS = 120
CHUNK_HOURS = 3
CHUNK_ACCOUNTS = 40
# Campaigns appear in every third chunk, so the stream is mostly benign with periodic bursts.
ATTACK_EVERY_CHUNKS = 3


def replay_events(scenario: str, seed: int) -> tuple[AuthEvent, ...]:
    if scenario not in REPLAY_SCENARIOS:
        raise ValueError(f"unknown replay scenario {scenario!r}")
    config = GeneratorConfig(seed=seed, start_utc=START_UTC, duration_hours=REPLAY_HOURS, n_accounts=REPLAY_ACCOUNTS, n_events=REPLAY_EVENTS)
    return generate(config, REPLAY_SCENARIOS[scenario]).events


class ReplaySource:
    """A finished, ordered sequence released front to back."""

    def __init__(self, events: Iterable[AuthEvent]) -> None:
        self._events = tuple(events)
        self._cursor = 0

    def generated(self) -> int:
        return len(self._events)

    def pending(self) -> int:
        return len(self._events) - self._cursor

    def take(self, count: int) -> tuple[AuthEvent, ...]:
        batch = self._events[self._cursor : self._cursor + count]
        self._cursor += len(batch)
        return batch


class ContinuousSource:
    """Deterministic chunks produced on demand. Chunk ``i`` depends only on the seed and ``i``."""

    def __init__(self, seed: int, attacks: frozenset[str]) -> None:
        self._seed = seed
        self._attacks = attacks
        self._next_chunk = 0
        self._generated = 0
        self._queue: deque[AuthEvent] = deque()

    def generated(self) -> int:
        return self._generated

    def pending(self) -> int:
        return len(self._queue)

    def take(self, count: int) -> tuple[AuthEvent, ...]:
        while len(self._queue) < count:
            chunk = self._make_chunk(self._next_chunk)
            self._next_chunk += 1
            self._generated += len(chunk)
            self._queue.extend(chunk)
        return tuple(self._queue.popleft() for _ in range(count))

    def _make_chunk(self, index: int) -> tuple[AuthEvent, ...]:
        plan = self._plan() if index % ATTACK_EVERY_CHUNKS == ATTACK_EVERY_CHUNKS - 1 else ScenarioPlan()
        config = GeneratorConfig(
            seed=_chunk_seed(self._seed, index),
            start_utc=START_UTC + timedelta(hours=CHUNK_HOURS * index),
            duration_hours=CHUNK_HOURS,
            n_accounts=CHUNK_ACCOUNTS,
            n_events=CHUNK_EVENTS,
        )
        # Namespacing keeps ids unique across chunks and stops accounts from being merged by mistake.
        prefix = f"c{index:06d}-"
        return tuple(
            replace(event, event_id=prefix + event.event_id, account_id=prefix + event.account_id)
            for event in generate(config, plan).events
        )

    def _plan(self) -> ScenarioPlan:
        return ScenarioPlan(
            bruteforce_campaigns=int("bruteforce" in self._attacks),
            password_spraying_campaigns=int("password_spraying" in self._attacks),
            impossible_travel_campaigns=int("impossible_travel" in self._attacks),
        )


def _chunk_seed(seed: int, index: int) -> int:
    digest = hashlib.sha256(f"{seed}|chunk|{index}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % (MAX_SEED + 1)
