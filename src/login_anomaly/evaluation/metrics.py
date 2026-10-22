"""Binary detection metrics. Plain counting, no third-party dependency.

Convention: 1 is malicious (positive), 0 is benign. Undefined ratios (no
predicted positives, no true positives) are reported as 0.0, never NaN.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfusionMatrix:
    tp: int
    fp: int
    fn: int
    tn: int


def confusion(truth: Sequence[int], predicted: Sequence[int]) -> ConfusionMatrix:
    if len(truth) != len(predicted):
        raise ValueError("truth and predicted must have the same length")
    if any(value not in (0, 1) for value in (*truth, *predicted)):
        raise ValueError("values must be 0 or 1")
    tp = sum(1 for t, p in zip(truth, predicted) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(truth, predicted) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(truth, predicted) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(truth, predicted) if t == 0 and p == 0)
    return ConfusionMatrix(tp=tp, fp=fp, fn=fn, tn=tn)


def precision(cm: ConfusionMatrix) -> float:
    return cm.tp / (cm.tp + cm.fp) if cm.tp + cm.fp else 0.0


def recall(cm: ConfusionMatrix) -> float:
    return cm.tp / (cm.tp + cm.fn) if cm.tp + cm.fn else 0.0


def f1(cm: ConfusionMatrix) -> float:
    p, r = precision(cm), recall(cm)
    return 2 * p * r / (p + r) if p + r else 0.0
