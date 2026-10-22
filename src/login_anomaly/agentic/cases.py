"""Label-free investigation inputs derived from correlated detector cases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from login_anomaly.correlation import InvestigationCase
from login_anomaly.events import AuthEvent
from login_anomaly.validation import require_identifier, require_utc


@dataclass(frozen=True)
class CaseInvestigationInput:
    """The entire runtime input for a case investigator; it intentionally has no labels."""

    case_id: str
    dataset_id: str
    case_kind: str
    event_ids: tuple[str, ...]
    priority_hint: str
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self) -> None:
        require_identifier(self.case_id, "case_id")
        require_identifier(self.dataset_id, "dataset_id")
        if self.case_kind not in {"rule_backed", "ml_only"}:
            raise ValueError("case_kind must be 'rule_backed' or 'ml_only'")
        if not self.event_ids:
            raise ValueError("event_ids must not be empty")
        for event_id in self.event_ids:
            require_identifier(event_id, "event_ids item")
        require_utc(self.first_seen, "first_seen")
        require_utc(self.last_seen, "last_seen")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")


def case_input_for(case: InvestigationCase, events: tuple[AuthEvent, ...]) -> CaseInvestigationInput:
    """Bind a provenance-safe case to observable timestamps for an investigation."""
    by_id = {event.event_id: event for event in events}
    named = [by_id[event_id] for event_id in case.event_ids]
    return CaseInvestigationInput(
        case_id=case.case_id,
        dataset_id=case.dataset_id,
        case_kind=case.case_kind,
        event_ids=case.event_ids,
        priority_hint=case.priority_hint,
        first_seen=min(event.timestamp_utc for event in named),
        last_seen=max(event.timestamp_utc for event in named),
    )
