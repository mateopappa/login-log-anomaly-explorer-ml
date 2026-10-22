"""Case-aware mock investigator and reviewer contracts stay label-free and bounded."""

from datetime import datetime, timezone

from login_anomaly.agentic.case_investigator import run_case_investigation
from login_anomaly.agentic.cases import CaseInvestigationInput
from login_anomaly.agentic.provider import FinalResponse, ToolRequest
from login_anomaly.agentic.reviewer import review_case_investigation
from login_anomaly.events import AuthEvent, Outcome

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)
CASE = CaseInvestigationInput("case-1", "dataset-1", "ml_only", ("evt-1",), "ml_untriaged", T0, T0)
EVENTS = (AuthEvent("evt-1", T0, "acct-1", "10.0.0.1", Outcome.FAILURE, "AR"),)


class ScriptedProvider:
    mode = "mock"
    provider_id = "test-provider"

    def __init__(self, *actions) -> None:  # type: ignore[no-untyped-def]
        self.actions = list(actions)

    def next_action(self, case, observations):  # type: ignore[no-untyped-def]
        return self.actions.pop(0)


def final(case_id: str = "case-1") -> FinalResponse:
    return FinalResponse(
        {
            "alert_id": case_id,
            "verdict": "inconclusive",
            "confidence": 0.0,
            "evidence": [],
            "tool_calls": [],
            "justification": "Insufficient evidence.",
            "limitations": ["Insufficient evidence."],
        }
    )


def test_ml_only_case_can_be_investigated_with_a_dynamic_read_only_call() -> None:
    provider = ScriptedProvider(ToolRequest("get_alert_evidence", {"alert_id": "case-1"}), final())
    run = run_case_investigation(EVENTS, CASE, provider)
    assert run.result.alert_id == CASE.case_id
    assert [call.tool_name for call in run.result.tool_calls] == ["get_alert_evidence"]
    assert run.tool_results[0]["events"][0]["event_id"] == "evt-1"
    review = review_case_investigation(run)
    assert review.case_id == CASE.case_id and review.mode == "deterministic"


def test_invalid_final_output_is_safely_abstained() -> None:
    run = run_case_investigation(EVENTS, CASE, ScriptedProvider(FinalResponse({})))
    assert run.result.verdict == "inconclusive"
    assert any("invalid provider result" in error for error in run.errors)


def test_forbidden_or_malformed_tool_request_is_denied() -> None:
    run = run_case_investigation(EVENTS, CASE, ScriptedProvider(ToolRequest("get_ground_truth", {})))
    assert run.result.verdict == "inconclusive"
    assert run.result.tool_calls[0].status == "denied"


def test_tool_and_step_budgets_stop_the_loop() -> None:
    run = run_case_investigation(EVENTS, CASE, ScriptedProvider(ToolRequest("get_alert_evidence", {"alert_id": "case-1"}), final()), max_tool_calls=0)
    assert run.result.verdict == "inconclusive"
    assert "budget" in run.errors[0]
    step_limited = run_case_investigation(EVENTS, CASE, ScriptedProvider(ToolRequest("get_alert_evidence", {"alert_id": "case-1"})), max_steps=1)
    assert step_limited.result.verdict == "inconclusive"
    assert step_limited.errors == ("step budget exhausted",)


def test_provider_exception_is_abstained_not_raised() -> None:
    class FailingProvider(ScriptedProvider):
        def next_action(self, case, observations):  # type: ignore[no-untyped-def]
            raise TimeoutError("simulated transport failure")

    run = run_case_investigation(EVENTS, CASE, FailingProvider())
    assert run.result.verdict == "inconclusive"
    assert run.errors == ("provider failed: TimeoutError",)


def test_review_flags_zero_confidence_verdict_and_policy_findings() -> None:
    contradicting = FinalResponse(
        {
            "alert_id": "case-1",
            "verdict": "malicious",
            "confidence": 0.0,
            "evidence": [{"event_id": "evt-1", "field": "outcome", "summary": "Observed failure."}],
            "tool_calls": [],
            "justification": "Evidence is present but confidence is not.",
            "limitations": ["Single event."],
        }
    )
    run = run_case_investigation(EVENTS, CASE, ScriptedProvider(contradicting))
    review = review_case_investigation(run)
    assert review.quality == "needs_review"
    assert review.contradictions == ("Non-abstaining verdict with zero confidence.",)
    assert review.uncertainty == ("Single event.",)
    assert review.policy_findings == ()
