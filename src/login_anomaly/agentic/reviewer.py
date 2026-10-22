"""Independent runtime review of investigation quality without ground truth."""

from __future__ import annotations

from dataclasses import dataclass

from login_anomaly.agentic.case_investigator import CaseInvestigationRun


@dataclass(frozen=True)
class InvestigationReview:
    case_id: str
    mode: str
    quality: str
    strengths: tuple[str, ...]
    deficiencies: tuple[str, ...]
    unsupported_claims: tuple[str, ...]
    omissions: tuple[str, ...]
    contradictions: tuple[str, ...]
    uncertainty: tuple[str, ...]
    policy_findings: tuple[str, ...]


def review_case_investigation(run: CaseInvestigationRun) -> InvestigationReview:
    """Review citations, uncertainty, and policy traces without any hidden labels."""
    result = run.result
    cited = {item.event_id for item in result.evidence}
    allowed = set(run.case.event_ids)
    unsupported = ("Evidence cites event ids outside the case.",) if not cited <= allowed else ()
    deficiencies = []
    omissions = []
    contradictions = []
    strengths = []
    if result.tool_calls:
        strengths.append("Used the bounded read-only tool interface.")
    if result.evidence:
        strengths.append("Cited observable event evidence.")
    if result.verdict == "inconclusive":
        strengths.append("Abstained when the available evidence was insufficient.")
    else:
        if not result.evidence:
            deficiencies.append("Reached a non-abstaining conclusion without evidence.")
        if result.confidence == 0.0:
            contradictions.append("Non-abstaining verdict with zero confidence.")
    if run.case.case_kind == "ml_only" and result.verdict != "inconclusive":
        omissions.append("ML-only case should explain why event-level evidence supports a conclusion.")
    uncertainty = tuple(result.limitations) or ("No limitations or uncertainty stated.",)
    if not result.limitations:
        deficiencies.append("No limitations or uncertainty stated.")
    # Denied, failed, or over-budget steps are policy-relevant even when the verdict is sound.
    policy_findings = tuple(run.errors)
    quality = "needs_review" if deficiencies or unsupported or omissions or contradictions or policy_findings else "adequate"
    return InvestigationReview(
        run.case.case_id,
        "deterministic",
        quality,
        tuple(strengths),
        tuple(deficiencies),
        unsupported,
        tuple(omissions),
        tuple(contradictions),
        uncertainty,
        policy_findings,
    )
