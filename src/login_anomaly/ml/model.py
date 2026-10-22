"""Supervised baseline model: a random forest over the causal event features.

Deliberately small. It is a defensible baseline, not a tuned production model.
Hyperparameters are fixed constants so that results are reproducible.
"""

from __future__ import annotations

from collections.abc import Sequence

from sklearn.ensemble import RandomForestClassifier

RANDOM_FOREST_PARAMS: dict[str, object] = {
    "n_estimators": 100,
    "max_depth": 6,
    "min_samples_leaf": 5,
    "class_weight": "balanced",
}
DECISION_THRESHOLD = 0.5


def train_model(features: Sequence[Sequence[float]], labels: Sequence[int], seed: int) -> RandomForestClassifier:
    model = RandomForestClassifier(random_state=seed, **RANDOM_FOREST_PARAMS)  # type: ignore[arg-type]
    model.fit(list(features), list(labels))
    return model


def predict_malicious(model: RandomForestClassifier, features: Sequence[Sequence[float]]) -> list[int]:
    if not features:
        return []
    positive_column = list(model.classes_).index(1)
    scores = model.predict_proba(list(features))[:, positive_column]
    return [1 if score >= DECISION_THRESHOLD else 0 for score in scores]
