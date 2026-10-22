"""Label-free runtime orchestration for one detector workflow run.

This module connects existing runtime components without changing their behavior:
rules retain their native alerts, ML retains event-level positive signals, and only
native rule alerts are sent to the current deterministic investigator.  Evaluation,
ground truth, campaign labels, and correlation intentionally do not belong here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sklearn.ensemble import RandomForestClassifier

from login_anomaly.agentic.case_investigator import CaseInvestigationRun, run_case_investigation
from login_anomaly.agentic.cases import case_input_for
from login_anomaly.agentic.investigator import AlertInvestigation, investigate_alerts
from login_anomaly.agentic.provider import InvestigatorProvider, MockInvestigatorProvider
from login_anomaly.agentic.reviewer import InvestigationReview, review_case_investigation
from login_anomaly.correlation import InvestigationCase, MlPositiveSignal, correlate_signals, dataset_id_for, make_ml_positive_signal
from login_anomaly.detection.rules import Alert, detect
from login_anomaly.ml.features import FEATURE_NAMES, feature_matrix
from login_anomaly.ml.model import DECISION_THRESHOLD, predict_malicious
from login_anomaly.simulation.generator import EventDataset
from login_anomaly.simulation.manifest import DatasetManifest
from login_anomaly.validation import require_identifier


class WorkflowError(ValueError):
    """Raised when a runtime workflow input cannot be represented faithfully."""


@dataclass(frozen=True)
class ModelRunMetadata:
    """Caller-provided identity and fixed inference metadata for one model run."""

    model_run_id: str
    decision_threshold: float = field(default=DECISION_THRESHOLD, init=False)
    feature_names: tuple[str, ...] = field(default=FEATURE_NAMES, init=False)

    def __post_init__(self) -> None:
        require_identifier(self.model_run_id, "model_run_id")


@dataclass(frozen=True)
class DetectionWorkflowResult:
    """Immutable, label-free record of one generation-to-investigation workflow run."""

    dataset_id: str
    manifest: DatasetManifest
    model_run: ModelRunMetadata
    event_ids: tuple[str, ...]
    rule_alerts: tuple[Alert, ...]
    ml_positive_signals: tuple[MlPositiveSignal, ...]
    cases: tuple[InvestigationCase, ...]
    investigations: tuple[AlertInvestigation, ...]
    case_investigations: tuple[CaseInvestigationRun, ...]
    case_reviews: tuple[InvestigationReview, ...]


def run_detection_workflow(
    dataset: EventDataset,
    model: RandomForestClassifier,
    model_run: ModelRunMetadata,
    *,
    investigator_provider: InvestigatorProvider | None = None,
) -> DetectionWorkflowResult:
    """Run rules, ML inference, and rule-alert investigation on observable events only.

    ML positives are constructed with the existing provenance-checked signal factory.
    Cases use exact event-id association only; native rule alerts remain unchanged.
    """
    if not isinstance(dataset, EventDataset):
        raise WorkflowError("dataset must be an EventDataset")
    if not isinstance(model_run, ModelRunMetadata):
        raise WorkflowError("model_run must be a ModelRunMetadata")

    dataset_id = dataset_id_for(dataset.manifest)
    alerts = tuple(detect(dataset.events))
    event_ids, rows = feature_matrix(dataset.events)
    predictions = predict_malicious(model, rows)
    ml_positive_signals = tuple(
        make_ml_positive_signal(dataset_id, event_id, model_run.model_run_id, model_run.decision_threshold)
        for event_id, prediction in zip(event_ids, predictions)
        if prediction == 1
    )
    cases = correlate_signals(dataset.events, alerts, ml_positive_signals, dataset_id=dataset_id)
    investigations = investigate_alerts(dataset.events, alerts)
    provider: InvestigatorProvider = MockInvestigatorProvider() if investigator_provider is None else investigator_provider
    case_investigations = tuple(
        run_case_investigation(dataset.events, case_input_for(case, dataset.events), provider)
        for case in cases
    )
    case_reviews = tuple(review_case_investigation(run) for run in case_investigations)
    return DetectionWorkflowResult(
        dataset_id=dataset_id,
        manifest=dataset.manifest,
        model_run=model_run,
        event_ids=tuple(event_ids),
        rule_alerts=alerts,
        ml_positive_signals=ml_positive_signals,
        cases=cases,
        investigations=investigations,
        case_investigations=case_investigations,
        case_reviews=case_reviews,
    )
