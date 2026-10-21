"""Ground-truth labels for synthetic events, schema version 1.0.0.

These labels are for evaluation only. They must never reach detector or
investigator code, which receives ``AuthEvent`` objects and nothing else from
the simulation.

``is_malicious`` is derived from ``scenario_type``: every attack scenario is
malicious and ``benign`` is not. The field is kept because it is part of the
approved contract. The constructor rejects any combination that contradicts
the scenario type, so the two cannot disagree.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class ScenarioType(Enum):
    BENIGN = "benign"
    BRUTEFORCE = "bruteforce"
    PASSWORD_SPRAYING = "password_spraying"
    IMPOSSIBLE_TRAVEL = "impossible_travel"


@dataclass(frozen=True)
class ScenarioLabel:
    """Truth for one event. ``campaign_id`` is None only for benign traffic."""

    event_id: str
    scenario_type: ScenarioType
    campaign_id: str | None
    is_malicious: bool

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id:
            raise ValueError("event_id must be a non-empty string")
        if not isinstance(self.scenario_type, ScenarioType):
            raise ValueError("scenario_type must be a ScenarioType member")
        if not isinstance(self.is_malicious, bool):
            raise ValueError("is_malicious must be a bool")
        if self.scenario_type is ScenarioType.BENIGN:
            if self.campaign_id is not None:
                raise ValueError("benign labels must not have a campaign_id")
            if self.is_malicious:
                raise ValueError("benign labels must not be malicious")
        else:
            if not isinstance(self.campaign_id, str) or not self.campaign_id:
                raise ValueError("attack labels need a non-empty campaign_id")
            if not self.is_malicious:
                raise ValueError("attack labels must be malicious")


class GroundTruth:
    """Read-only index of labels by ``event_id``.

    Duplicate ``event_id`` values are rejected at construction.
    ``label_for`` raises ``KeyError`` for an unknown ``event_id``, so a missing
    label is never silently treated as benign. ``in`` returns False for
    non-string keys instead of raising.
    """

    __slots__ = ("_by_event_id",)

    def __init__(self, labels: Iterable[ScenarioLabel]) -> None:
        index: dict[str, ScenarioLabel] = {}
        for label in labels:
            if not isinstance(label, ScenarioLabel):
                raise ValueError("GroundTruth accepts only ScenarioLabel entries")
            if label.event_id in index:
                raise ValueError(f"duplicate event_id in ground truth: {label.event_id!r}")
            index[label.event_id] = label
        self._by_event_id = index

    def label_for(self, event_id: str) -> ScenarioLabel:
        try:
            return self._by_event_id[event_id]
        except KeyError:
            raise KeyError(f"no ground-truth label for event_id {event_id!r}") from None

    def __contains__(self, event_id: object) -> bool:
        return isinstance(event_id, str) and event_id in self._by_event_id

    def __len__(self) -> int:
        return len(self._by_event_id)
