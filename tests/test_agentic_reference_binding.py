"""The evaluator must never score a result against the reference of a different alert."""

from datetime import datetime, timezone

import pytest

from login_anomaly.agentic.contracts import EvidenceReference, InvestigationInput, InvestigationResult
from login_anomaly.evaluation.agentic import AlertReference, evaluate_investigation

T = datetime(2026, 1, 1, tzinfo=timezone.utc)
INPUT = InvestigationInput(
    alert_id="alt-0001", rule_id="bruteforce", severity="high",
    event_ids=("evt-1", "evt-2"), first_seen=T, last_seen=T,
)
RESULT = InvestigationResult(
    alert_id="alt-0001", verdict="malicious", confidence=0.9,
    evidence=(EvidenceReference(event_id="evt-2", field="outcome", summary="failure"),),
    tool_calls=(), justification="Repeated failures.", limitations=(),
)


def test_reference_for_a_different_alert_is_rejected() -> None:
    other_alert = AlertReference(alert_id="alt-0002", is_true_alert=False, malicious_event_ids=frozenset())
    with pytest.raises(ValueError, match="different alert"):
        evaluate_investigation(RESULT, other_alert, INPUT)


def test_matching_reference_is_scored() -> None:
    reference = AlertReference(alert_id="alt-0001", is_true_alert=True, malicious_event_ids=frozenset({"evt-2"}))
    assert evaluate_investigation(RESULT, reference, INPUT).verdict_correct is True
