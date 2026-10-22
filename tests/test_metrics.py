"""Metrics used by the conventional evaluator. Hand-computed expected values, no shortcuts."""

import math

import pytest

from login_anomaly.evaluation.metrics import ConfusionMatrix, confusion, f1, precision, recall


def test_confusion_counts_match_hand_computed_values() -> None:
    # truth:      1 1 1 0 0 0 0 0
    # prediction: 1 1 0 1 0 0 0 0
    cm = confusion(truth=[1, 1, 1, 0, 0, 0, 0, 0], predicted=[1, 1, 0, 1, 0, 0, 0, 0])
    assert cm == ConfusionMatrix(tp=2, fp=1, fn=1, tn=4)


def test_precision_recall_f1_from_known_counts() -> None:
    cm = ConfusionMatrix(tp=2, fp=1, fn=1, tn=4)
    assert precision(cm) == pytest.approx(2 / 3)
    assert recall(cm) == pytest.approx(2 / 3)
    assert f1(cm) == pytest.approx(2 / 3)


def test_zero_division_returns_zero_not_nan() -> None:
    empty_predictions = ConfusionMatrix(tp=0, fp=0, fn=5, tn=10)
    assert precision(empty_predictions) == 0.0
    assert not math.isnan(f1(empty_predictions))
    assert f1(empty_predictions) == 0.0
    no_positives = ConfusionMatrix(tp=0, fp=3, fn=0, tn=10)
    assert recall(no_positives) == 0.0


def test_perfect_detector_scores_one() -> None:
    cm = confusion(truth=[1, 0, 1, 0], predicted=[1, 0, 1, 0])
    assert precision(cm) == recall(cm) == f1(cm) == 1.0


def test_confusion_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError, match="same length"):
        confusion(truth=[1, 0], predicted=[1])


def test_confusion_rejects_non_binary_values() -> None:
    with pytest.raises(ValueError, match="0 or 1"):
        confusion(truth=[2], predicted=[1])
