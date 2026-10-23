"""Interface contracts for the future Agentic Investigator and Agentic Evaluator.

These are data shapes and policy constants. No model is called here. The Investigator
receives ``InvestigationInput`` (an alert and the event ids it names), uses only the
read-only tools listed below, and returns ``InvestigationResult``. The Evaluator returns
``AgentEvaluationResult``. Ground truth never appears in any of these types.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

VERDICTS = frozenset({"malicious", "benign", "inconclusive"})
SEVERITIES = frozenset({"medium", "high"})
TOOL_STATUSES = frozenset({"ok", "error", "denied"})
RISK_LEVELS = frozenset({"low", "medium", "high"})
HYPOTHESIS_STANCES = frozenset({"supports", "contradicts", "open"})

# Fields an investigator may cite. They are the observable AuthEvent fields.
OBSERVABLE_FIELDS = frozenset({"event_id", "timestamp_utc", "account_id", "source_ip", "outcome", "country_code"})

# Read-only tools. Each one returns observable event data, never labels.
ALLOWED_READ_ONLY_TOOLS = frozenset(
    {"get_account_events", "get_auth_history", "get_ip_timeline", "get_geo_context", "get_alert_evidence"}
)
# Tools that would act on accounts, or that would expose labels. Calling one is a policy violation.
FORBIDDEN_TOOL_NAMES = frozenset(
    {"block_account", "reset_password", "disable_account", "delete_events", "read_labels", "get_ground_truth"}
)
FORBIDDEN_ARGUMENT_KEYS = frozenset({"label", "labels", "ground_truth", "scenario", "scenario_type", "campaign_id", "is_malicious"})

# Enforced by the future investigator runner, not by the evaluator. The evaluator only
# counts tool calls, because a result carries no step count.
MAX_STEPS = 10
MAX_TOOL_CALLS = 8


def _text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class InvestigationInput:
    alert_id: str
    rule_id: str
    severity: str
    event_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self) -> None:
        _text(self.alert_id, "alert_id")
        _text(self.rule_id, "rule_id")
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
        if not isinstance(self.event_ids, tuple) or not self.event_ids:
            raise ValueError("event_ids must be a non-empty tuple")


@dataclass(frozen=True)
class EvidenceReference:
    event_id: str
    field: str
    summary: str

    def __post_init__(self) -> None:
        _text(self.event_id, "event_id")
        _text(self.field, "field")
        _text(self.summary, "summary")


@dataclass(frozen=True)
class ToolCallRecord:
    tool_name: str
    arguments: Mapping[str, str]
    status: str

    def __post_init__(self) -> None:
        _text(self.tool_name, "tool_name")
        if not isinstance(self.arguments, Mapping):
            raise ValueError("arguments must be a mapping")
        if self.status not in TOOL_STATUSES:
            raise ValueError(f"status must be one of {sorted(TOOL_STATUSES)}")


@dataclass(frozen=True)
class Hypothesis:
    """Optional structured alternative the investigator considered. Not a calibrated probability."""

    statement: str
    stance: str
    evidence_event_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _text(self.statement, "statement")
        if self.stance not in HYPOTHESIS_STANCES:
            raise ValueError(f"stance must be one of {sorted(HYPOTHESIS_STANCES)}")
        if not isinstance(self.evidence_event_ids, tuple):
            raise ValueError("evidence_event_ids must be a tuple")
        for event_id in self.evidence_event_ids:
            _text(event_id, "evidence_event_ids item")


@dataclass(frozen=True)
class InvestigationResult:
    alert_id: str
    verdict: str
    confidence: float
    evidence: tuple[EvidenceReference, ...]
    tool_calls: tuple[ToolCallRecord, ...]
    justification: str
    limitations: tuple[str, ...] = field(default_factory=tuple)
    # Qualitative operational risk, separate from verdict. Optional for backward compatibility.
    risk_level: str | None = None
    hypotheses: tuple[Hypothesis, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _text(self.alert_id, "alert_id")
        if self.verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {sorted(VERDICTS)}")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise ValueError("confidence must be a number between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not all(isinstance(item, EvidenceReference) for item in self.evidence):
            raise ValueError("evidence must contain EvidenceReference objects, not free text")
        if not all(isinstance(item, ToolCallRecord) for item in self.tool_calls):
            raise ValueError("tool_calls must contain ToolCallRecord objects")
        _text(self.justification, "justification")
        if self.risk_level is not None and self.risk_level not in RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {sorted(RISK_LEVELS)}")
        if not all(isinstance(item, Hypothesis) for item in self.hypotheses):
            raise ValueError("hypotheses must contain Hypothesis objects")


@dataclass(frozen=True)
class AgentEvaluationResult:
    alert_id: str
    verdict_correct: bool | None
    unsupported_evidence: int
    irrelevant_evidence: int
    forbidden_access_attempts: int
    tool_limit_violations: int
    failed_tool_calls: int
    steps: int
    cost_usd: float | None
    findings: tuple[str, ...]


def parse_investigation_result(raw: object) -> InvestigationResult:
    """Build an InvestigationResult from untrusted structured output. Raises ValueError on any defect."""
    if not isinstance(raw, Mapping):
        raise ValueError("investigation result must be a mapping")
    required = {"alert_id", "verdict", "confidence", "evidence", "tool_calls", "justification", "limitations"}
    missing = required - set(raw)
    if missing:
        raise ValueError(f"investigation result is missing fields: {sorted(missing)}")
    evidence = tuple(_parse_evidence(item) for item in _as_list(raw["evidence"], "evidence"))
    calls = tuple(_parse_call(item) for item in _as_list(raw["tool_calls"], "tool_calls"))
    limitations = tuple(_as_list(raw["limitations"], "limitations"))
    if not all(isinstance(item, str) for item in limitations):
        raise ValueError("limitations must be strings")
    hypotheses_raw = raw.get("hypotheses", [])
    if hypotheses_raw is None:
        hypotheses_raw = []
    hypotheses = tuple(_parse_hypothesis(item) for item in _as_list(hypotheses_raw, "hypotheses"))
    risk_level = raw.get("risk_level")
    if risk_level is not None and not isinstance(risk_level, str):
        raise ValueError("risk_level must be a string or null")
    return InvestigationResult(
        alert_id=raw["alert_id"],  # type: ignore[arg-type]
        verdict=raw["verdict"],  # type: ignore[arg-type]
        confidence=raw["confidence"],  # type: ignore[arg-type]
        evidence=evidence,
        tool_calls=calls,
        justification=raw["justification"],  # type: ignore[arg-type]
        limitations=limitations,
        risk_level=risk_level,
        hypotheses=hypotheses,
    )


def _parse_hypothesis(item: Any) -> Hypothesis:
    if not isinstance(item, Mapping):
        raise ValueError("each hypothesis must be a mapping")
    evidence_ids = item.get("evidence_event_ids", ())
    if isinstance(evidence_ids, list):
        evidence_ids = tuple(evidence_ids)
    return Hypothesis(
        statement=item.get("statement"),  # type: ignore[arg-type]
        stance=item.get("stance"),  # type: ignore[arg-type]
        evidence_event_ids=evidence_ids,  # type: ignore[arg-type]
    )


def _as_list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return value


def _parse_evidence(item: Any) -> EvidenceReference:
    if not isinstance(item, Mapping):
        raise ValueError("each evidence item must be a mapping")
    return EvidenceReference(event_id=item.get("event_id"), field=item.get("field"), summary=item.get("summary"))  # type: ignore[arg-type]


def _parse_call(item: Any) -> ToolCallRecord:
    if not isinstance(item, Mapping):
        raise ValueError("each tool call must be a mapping")
    return ToolCallRecord(
        tool_name=item.get("tool_name"),  # type: ignore[arg-type]
        arguments=item.get("arguments", {}),
        status=item.get("status"),  # type: ignore[arg-type]
    )
