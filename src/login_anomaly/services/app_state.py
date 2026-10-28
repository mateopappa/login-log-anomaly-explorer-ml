"""Process-local runtime state for the API (live engine + settings)."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from login_anomaly.config import Settings, load_settings
from login_anomaly.live.engine import SimulationService


@dataclass
class AppState:
    settings: Settings
    live: SimulationService | None = None
    trained_model: Any = field(default=None, repr=False)
    last_seed_dataset_id: str | None = None
    # One live tick at a time. The shell timer and Advance once share this process.
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def ensure_model(self) -> Any:
        if self.trained_model is None:
            # Training uses labels only inside evaluation.experiment (allowed package).
            from login_anomaly.evaluation.experiment import train_baseline

            model, _, _ = train_baseline()
            self.trained_model = model
        return self.trained_model


_STATE: AppState | None = None


def get_state() -> AppState:
    global _STATE
    if _STATE is None:
        _STATE = AppState(settings=load_settings())
    return _STATE


def reset_state() -> None:
    global _STATE
    _STATE = None
