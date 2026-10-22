"""Provider-independent, structured actions for the case investigator.

No provider is configured here.  The deterministic mock is local-only and makes
the bounded agent loop testable without credentials or paid calls.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from login_anomaly.agentic.cases import CaseInvestigationInput


@dataclass(frozen=True)
class ToolRequest:
    tool_name: str
    arguments: Mapping[str, object]


@dataclass(frozen=True)
class FinalResponse:
    result: Mapping[str, Any]


AgentAction = ToolRequest | FinalResponse


class InvestigatorProvider(Protocol):
    """A future real adapter implements this protocol with structured model output."""

    @property
    def mode(self) -> str: ...

    @property
    def provider_id(self) -> str: ...

    def next_action(self, case: CaseInvestigationInput, observations: tuple[Mapping[str, Any], ...]) -> AgentAction: ...


@dataclass(frozen=True)
class MockInvestigatorProvider:
    """Deterministic local provider used for tests and manual demos; not an LLM."""

    mode: str = "mock"
    provider_id: str = "deterministic-case-mock-v1"

    def next_action(self, case: CaseInvestigationInput, observations: tuple[Mapping[str, Any], ...]) -> AgentAction:
        if not observations:
            return ToolRequest("get_alert_evidence", {"alert_id": case.case_id})
        evidence_rows = observations[-1].get("events", ())
        evidence = [
            {"event_id": row["event_id"], "field": "outcome", "summary": f"Observed {row['outcome']} authentication event."}
            for row in evidence_rows
        ]
        verdict = "malicious" if case.case_kind == "rule_backed" and evidence else "inconclusive"
        limitations = ["Mock provider: deterministic local behavior, not an LLM."]
        if case.case_kind == "ml_only":
            limitations.append("ML-positive evidence alone is insufficient for a confident conclusion.")
        return FinalResponse(
            {
                "alert_id": case.case_id,
                "verdict": verdict,
                "confidence": 0.6 if verdict == "malicious" else 0.0,
                "evidence": evidence,
                "tool_calls": [],
                "justification": "Evidence was retrieved through the bounded read-only interface.",
                "limitations": limitations,
            }
        )
