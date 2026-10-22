"""Deterministic investigator: a rule-based stand-in for the future Agentic Investigator.

No language model is called. It takes one alert (as ``InvestigationInput``) and the
observable events, reads them only through the read-only tools in ``tools.py``, and
returns an ``InvestigationResult``. It never sees ground truth, and it does not depend on
the generator, so any source of ``AuthEvent`` objects can feed it.

Budget: every tool call is one step, and the conclusion is one more step. A tool call is
refused when it would exceed ``max_tool_calls`` or leave no step for the conclusion.

Verdict policy (a fixed heuristic, not a calibrated model):
- ``inconclusive`` when the alert cannot be reproduced from its own events, when an alert
  event is missing, when a planned tool call failed or was refused by the budget, when the
  rule has no playbook, or when the signals for and against cancel out;
- otherwise ``malicious`` or ``benign`` by the sign of the weighted signals.
Evidence cites only the alert's own events, the only ones the evaluator accepts as support.
Pivot findings (account and IP context) are reported in the justification.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from login_anomaly.agentic.contracts import (
    ALLOWED_READ_ONLY_TOOLS,
    MAX_STEPS,
    MAX_TOOL_CALLS,
    EvidenceReference,
    InvestigationInput,
    InvestigationResult,
    ToolCallRecord,
)
from login_anomaly.agentic.tools import MAX_WINDOW, TOOLS, Row, ToolContext
from login_anomaly.detection.rules import Alert
from login_anomaly.events import AuthEvent

# Context looked at around the alert window, clipped so the pivot window stays within MAX_WINDOW.
PIVOT_MARGIN = timedelta(hours=24)
CONFIDENCE_LIMITATION = "Confidence is a fixed heuristic of the signal count, not a calibrated probability."


@dataclass(frozen=True)
class InvestigationRun:
    """The result plus the budget outcome. The result itself carries no step count."""

    result: InvestigationResult
    steps: int
    failed_tools: tuple[str, ...] = ()
    refused_tools: tuple[str, ...] = ()  # calls not made because the budget was exhausted


@dataclass(frozen=True)
class AlertInvestigation:
    """One alert's investigation, or the error that prevented it. Never holds labels."""

    alert_id: str
    rule_id: str
    investigation_input: InvestigationInput | None
    run: InvestigationRun | None
    error: str | None = None


def investigation_input_for(alert: Alert) -> InvestigationInput:
    """Map a rule-detector alert to the investigator contract. Drops the detector's free text."""
    return InvestigationInput(
        alert_id=alert.alert_id,
        rule_id=alert.rule_id,
        severity=alert.severity.value,
        event_ids=alert.event_ids,
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
    )


def find_alert(alerts: Iterable[Alert], alert_id: str) -> Alert:
    """Return the alert with this id. An unknown id is a caller error and raises LookupError."""
    for alert in alerts:
        if alert.alert_id == alert_id:
            return alert
    raise LookupError(f"unknown alert id: {alert_id!r}")


def investigate_alerts(
    events: Iterable[AuthEvent],
    alerts: Iterable[Alert],
    *,
    max_steps: int = MAX_STEPS,
    max_tool_calls: int = MAX_TOOL_CALLS,
) -> tuple[AlertInvestigation, ...]:
    """Investigate each alert independently. A malformed alert is recorded as an error, not raised."""
    _check_budget(max_steps, max_tool_calls)
    observable = tuple(events)
    investigations = []
    for alert in alerts:
        try:
            investigation = investigation_input_for(alert)
            run = run_investigation(observable, investigation, max_steps=max_steps, max_tool_calls=max_tool_calls)
        except (ValueError, LookupError) as error:
            investigations.append(AlertInvestigation(alert.alert_id, alert.rule_id, None, None, f"{type(error).__name__}: {error}"))
        else:
            investigations.append(AlertInvestigation(alert.alert_id, alert.rule_id, investigation, run))
    return tuple(investigations)


class _Session:
    """Runs tool calls under the step and call budget and keeps the audit log."""

    def __init__(self, ctx: ToolContext, max_steps: int, max_tool_calls: int) -> None:
        self._ctx = ctx
        self._max_steps = max_steps
        self._max_tool_calls = max_tool_calls
        self.calls: list[ToolCallRecord] = []
        self.steps = 0
        self.refused: list[str] = []
        self.failed: list[str] = []

    def call(self, name: str, **arguments: Any) -> tuple[Row, ...] | None:
        if name not in ALLOWED_READ_ONLY_TOOLS:
            raise ValueError(f"{name} is not an allowed read-only tool")
        # One step is always reserved for the conclusion.
        if len(self.calls) >= self._max_tool_calls or self.steps + 1 >= self._max_steps:
            self.refused.append(name)
            return None
        self.steps += 1
        record, rows = TOOLS[name](self._ctx, **arguments)
        self.calls.append(record)
        if record.status != "ok":
            self.failed.append(name)
            return None
        return rows


@dataclass
class _Findings:
    confirmed: bool = False
    signals: list[tuple[int, str]] = field(default_factory=list)  # (+ malicious / - benign weight, fact)
    evidence: list[EvidenceReference] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _ts(row: Row) -> datetime:
    return datetime.fromisoformat(row["timestamp_utc"])


def _pivot_window(investigation: InvestigationInput) -> tuple[datetime, datetime]:
    span = investigation.last_seen - investigation.first_seen
    if span >= MAX_WINDOW:
        return investigation.first_seen, investigation.first_seen + MAX_WINDOW
    margin = min(PIVOT_MARGIN, (MAX_WINDOW - span) / 2)
    return investigation.first_seen - margin, investigation.last_seen + margin


def _bruteforce(s: _Session, inv: InvestigationInput, rows: Sequence[Row], f: _Findings) -> None:
    accounts = {r["account_id"] for r in rows}
    ips = {r["source_ip"] for r in rows}
    f.evidence = [EvidenceReference(r["event_id"], "outcome", f"{r['outcome']} login for {r['account_id']} from {r['source_ip']}") for r in rows]
    f.confirmed = len(accounts) == 1 and all(r["outcome"] == "failure" for r in rows)
    if not f.confirmed:
        f.limitations.append("The alert's events are not all failures on a single account.")
        return
    (account,) = accounts
    f.signals.append((1, f"{len(rows)} failed logins on {account} from {len(ips)} IP(s) between {inv.first_seen.isoformat()} and {inv.last_seen.isoformat()}."))
    start, end = _pivot_window(inv)
    context = s.call("get_account_events", account_id=account, start=start, end=end)
    if context is None:
        return
    earlier_ok = [r for r in context if r["outcome"] == "success" and r["source_ip"] in ips and _ts(r) < inv.first_seen]
    later_ok = [r for r in context if r["outcome"] == "success" and r["source_ip"] in ips and _ts(r) > inv.last_seen]
    if earlier_ok:
        f.signals.append((-2, f"{account} had {len(earlier_ok)} earlier successful login(s) from the same IP(s), so the source is known to the account."))
    else:
        f.signals.append((1, f"No earlier successful login for {account} from the alert IP(s) in the surrounding window."))
    if later_ok:
        f.signals.append((1, f"{len(later_ok)} successful login(s) from the alert IP(s) followed the failures; possible compromise."))


def _spraying(s: _Session, inv: InvestigationInput, rows: Sequence[Row], f: _Findings) -> None:
    accounts = {r["account_id"] for r in rows}
    ips = {r["source_ip"] for r in rows}
    f.evidence = [EvidenceReference(r["event_id"], "account_id", f"{r['outcome']} login for {r['account_id']} from {r['source_ip']}") for r in rows]
    f.confirmed = len(ips) == 1 and len(accounts) >= 2 and all(r["outcome"] == "failure" for r in rows)
    if not f.confirmed:
        f.limitations.append("The alert's events are not failures from one IP across several accounts.")
        return
    (ip,) = ips
    f.signals.append((1, f"{len(rows)} failed logins across {len(accounts)} accounts from {ip}."))
    start, end = _pivot_window(inv)
    timeline = s.call("get_ip_timeline", source_ip=ip, start=start, end=end)
    if timeline is None:
        return
    succeeded = {r["account_id"] for r in timeline if r["outcome"] == "success"}
    if len(succeeded) >= len(accounts):
        f.signals.append((-2, f"{ip} also has successful logins for {len(succeeded)} distinct accounts in the surrounding window, consistent with a shared address."))
    else:
        f.signals.append((1, f"{ip} has successful logins for only {len(succeeded)} account(s) in the surrounding window."))


def _travel(s: _Session, inv: InvestigationInput, rows: Sequence[Row], f: _Findings) -> None:
    accounts = {r["account_id"] for r in rows}
    countries = [r["country_code"] for r in rows]
    f.evidence = [EvidenceReference(r["event_id"], "country_code", f"{r['outcome']} login for {r['account_id']} from {r['country_code']} at {r['timestamp_utc']}") for r in rows]
    f.confirmed = len(rows) == 2 and len(accounts) == 1 and len(set(countries)) == 2 and all(r["outcome"] == "success" for r in rows)
    if not f.confirmed:
        f.limitations.append("The alert's events are not two successful logins of one account from two countries.")
        return
    (account,) = accounts
    gap = int((_ts(rows[1]) - _ts(rows[0])).total_seconds() // 60)
    f.signals.append((1, f"{account} logged in successfully from {countries[0]} and {countries[1]} {gap} minutes apart."))
    start, end = _pivot_window(inv)
    context = s.call("get_account_events", account_id=account, start=start, end=end)
    if context is not None:
        seen_before = {r["country_code"] for r in context if r["outcome"] == "success" and _ts(r) < inv.first_seen}
        if set(countries) <= seen_before:
            f.signals.append((-2, f"{account} already logged in successfully from both {countries[0]} and {countries[1]} before the alert; consistent with roaming."))
        else:
            f.signals.append((1, f"{account} had no earlier successful login from both countries in the surrounding window."))
    regions = []
    for country in countries:
        geo = s.call("get_geo_context", country_code=country)
        if geo is None:
            return
        regions.append(geo[0]["region"])
    if regions[0] != regions[1]:
        f.signals.append((1, f"{countries[0]} ({regions[0]}) and {countries[1]} ({regions[1]}) are in different synthetic regions."))
    else:
        f.signals.append((-1, f"{countries[0]} and {countries[1]} are in the same synthetic region ({regions[0]})."))


_PLAYBOOKS: dict[str, Callable[[_Session, InvestigationInput, Sequence[Row], _Findings], None]] = {
    "bruteforce": _bruteforce,
    "password_spraying": _spraying,
    "impossible_travel": _travel,
}


def _check_budget(max_steps: int, max_tool_calls: int) -> None:
    if not 1 <= max_steps <= MAX_STEPS:
        raise ValueError(f"max_steps must be between 1 and {MAX_STEPS}")
    if not 1 <= max_tool_calls <= MAX_TOOL_CALLS:
        raise ValueError(f"max_tool_calls must be between 1 and {MAX_TOOL_CALLS}")


def run_investigation(
    events: Iterable[AuthEvent],
    investigation: InvestigationInput,
    *,
    max_steps: int = MAX_STEPS,
    max_tool_calls: int = MAX_TOOL_CALLS,
) -> InvestigationRun:
    """Investigate one alert. Deterministic: the same events and input give the same run."""
    _check_budget(max_steps, max_tool_calls)
    session = _Session(ToolContext(events=tuple(events), investigation=investigation), max_steps, max_tool_calls)
    findings = _Findings()

    evidence = session.call("get_alert_evidence", alert_id=investigation.alert_id)
    if evidence is not None:
        rows = evidence[0]["events"]
        missing = sorted(set(investigation.event_ids) - {r["event_id"] for r in rows})
        playbook = _PLAYBOOKS.get(investigation.rule_id)
        if missing:
            findings.limitations.append(f"{len(missing)} alert event(s) are not in the available events: {', '.join(missing[:5])}.")
        elif playbook is None:
            findings.limitations.append(f"No investigation playbook for rule {investigation.rule_id!r}.")
        else:
            playbook(session, investigation, rows, findings)

    session.steps += 1  # the conclusion step, always reserved by the session
    return InvestigationRun(
        result=_conclude(investigation, session, findings),
        steps=session.steps,
        failed_tools=tuple(session.failed),
        refused_tools=tuple(session.refused),
    )


def _conclude(investigation: InvestigationInput, session: _Session, findings: _Findings) -> InvestigationResult:
    limitations = list(findings.limitations)
    if session.failed:
        limitations.append(f"Tool call(s) returned an error: {', '.join(session.failed)}.")
    if session.refused:
        limitations.append(f"Budget exhausted; not called: {', '.join(session.refused)}.")
    complete = findings.confirmed and not session.failed and not session.refused and not findings.limitations
    score = sum(weight for weight, _ in findings.signals)
    if not complete or score == 0:
        verdict, confidence = "inconclusive", 0.0
    else:
        verdict = "malicious" if score > 0 else "benign"
        confidence = round(min(0.9, 0.5 + 0.1 * abs(score)), 2)
        limitations.append(CONFIDENCE_LIMITATION)
    facts = [text for _, text in findings.signals] or ["The alert could not be assessed from the available data."]
    return InvestigationResult(
        alert_id=investigation.alert_id,
        verdict=verdict,
        confidence=confidence,
        evidence=tuple(findings.evidence),
        tool_calls=tuple(session.calls),
        justification=" ".join(facts),
        limitations=tuple(limitations),
    )
