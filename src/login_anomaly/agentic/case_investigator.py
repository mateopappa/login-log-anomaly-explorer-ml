"""Bounded tool-selection loop for provider-backed case investigation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from login_anomaly.agentic.cases import CaseInvestigationInput
from login_anomaly.agentic.contracts import MAX_STEPS, MAX_TOOL_CALLS, InvestigationInput, InvestigationResult, ToolCallRecord, parse_investigation_result
from login_anomaly.agentic.provider import FinalResponse, InvestigatorProvider, ToolRequest
from login_anomaly.agentic.tools import TOOLS, ToolContext
from login_anomaly.events import AuthEvent

_TOOL_ARGUMENTS = {
    "get_alert_evidence": frozenset({"alert_id"}),
    "get_account_events": frozenset({"account_id", "start", "end"}),
    "get_auth_history": frozenset({"account_id", "limit"}),
    "get_ip_timeline": frozenset({"source_ip", "start", "end"}),
    "get_geo_context": frozenset({"country_code"}),
}


@dataclass(frozen=True)
class CaseInvestigationRun:
    case: CaseInvestigationInput
    mode: str
    provider_id: str
    result: InvestigationResult
    steps: int
    tool_results: tuple[Mapping[str, Any], ...]
    errors: tuple[str, ...]


def _tool_context(events: tuple[AuthEvent, ...], case: CaseInvestigationInput) -> ToolContext:
    # Existing tools only need an opaque id, event ids, and a time window.  This
    # bridge deliberately contains no rule alert text or evaluation data.
    input_ = InvestigationInput(case.case_id, "case", "medium", case.event_ids, case.first_seen, case.last_seen)
    return ToolContext(events, input_)


def _inconclusive(case: CaseInvestigationInput, calls: list[ToolCallRecord], reason: str) -> InvestigationResult:
    return InvestigationResult(
        alert_id=case.case_id,
        verdict="inconclusive",
        confidence=0.0,
        evidence=(),
        tool_calls=tuple(calls),
        justification="The case could not be concluded safely from the available evidence.",
        limitations=(reason,),
    )


def run_case_investigation(
    events: tuple[AuthEvent, ...],
    case: CaseInvestigationInput,
    provider: InvestigatorProvider,
    *,
    max_steps: int = MAX_STEPS,
    max_tool_calls: int = MAX_TOOL_CALLS,
) -> CaseInvestigationRun:
    """Run only provider-selected, allowlisted tools and validate its final result."""
    if not 1 <= max_steps <= MAX_STEPS or not 0 <= max_tool_calls <= MAX_TOOL_CALLS:
        raise ValueError("invalid investigation budget")
    context = _tool_context(events, case)
    calls: list[ToolCallRecord] = []
    observations: list[Mapping[str, Any]] = []
    errors: list[str] = []
    for step in range(max_steps):
        try:
            action = provider.next_action(case, tuple(observations))
        except Exception as error:  # a real adapter may fail on its own (timeouts, transport); abstain
            errors.append(f"provider failed: {type(error).__name__}")
            result = _inconclusive(case, calls, errors[-1])
            return CaseInvestigationRun(case, provider.mode, provider.provider_id, result, step + 1, tuple(observations), tuple(errors))
        if isinstance(action, FinalResponse):
            try:
                parsed = parse_investigation_result(action.result)
                if parsed.alert_id != case.case_id:
                    raise ValueError("result names a different case")
                result = InvestigationResult(
                    alert_id=parsed.alert_id,
                    verdict=parsed.verdict,
                    confidence=parsed.confidence,
                    evidence=parsed.evidence,
                    tool_calls=tuple(calls),
                    justification=parsed.justification,
                    limitations=parsed.limitations,
                )
            except ValueError as error:
                errors.append(f"invalid provider result: {error}")
                result = _inconclusive(case, calls, errors[-1])
            return CaseInvestigationRun(case, provider.mode, provider.provider_id, result, step + 1, tuple(observations), tuple(errors))
        if not isinstance(action, ToolRequest):
            errors.append("provider returned an unsupported action")
            result = _inconclusive(case, calls, errors[-1])
            return CaseInvestigationRun(case, provider.mode, provider.provider_id, result, step + 1, tuple(observations), tuple(errors))
        if len(calls) >= max_tool_calls:
            errors.append("tool-call budget exhausted")
            result = _inconclusive(case, calls, errors[-1])
            return CaseInvestigationRun(case, provider.mode, provider.provider_id, result, step + 1, tuple(observations), tuple(errors))
        allowed = _TOOL_ARGUMENTS.get(action.tool_name)
        if allowed is None or set(action.arguments) != allowed:
            calls.append(ToolCallRecord(action.tool_name, {key: str(value) for key, value in action.arguments.items()}, "denied"))
            errors.append("provider requested a forbidden or malformed tool call")
            result = _inconclusive(case, calls, errors[-1])
            return CaseInvestigationRun(case, provider.mode, provider.provider_id, result, step + 1, tuple(observations), tuple(errors))
        try:
            record, rows = TOOLS[action.tool_name](context, **dict(action.arguments))
        except (TypeError, ValueError) as error:
            calls.append(ToolCallRecord(action.tool_name, {key: str(value) for key, value in action.arguments.items()}, "denied"))
            errors.append(f"tool arguments rejected: {error}")
            result = _inconclusive(case, calls, errors[-1])
            return CaseInvestigationRun(case, provider.mode, provider.provider_id, result, step + 1, tuple(observations), tuple(errors))
        calls.append(record)
        if record.status != "ok":
            errors.append(f"tool returned {record.status}: {action.tool_name}")
        for row in rows:
            observations.append(dict(row))
    errors.append("step budget exhausted")
    result = _inconclusive(case, calls, errors[-1])
    return CaseInvestigationRun(case, provider.mode, provider.provider_id, result, max_steps, tuple(observations), tuple(errors))
