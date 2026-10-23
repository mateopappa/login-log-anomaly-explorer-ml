"""Pydantic API contracts. Kept separate from ORM models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    version: str


class ReadyResponse(BaseModel):
    status: str
    database: str
    investigator: dict[str, Any]


class SeedRequest(BaseModel):
    seed: int = Field(default=42, ge=0, le=2_147_483_647)


class SeedResponse(BaseModel):
    dataset_id: str
    events: int
    cases: int
    rule_alerts: int
    ml_signals: int


class InvestigateRequest(BaseModel):
    provider: Literal["mock", "haiku"] | None = None
    idempotency_key: str | None = Field(default=None, max_length=128)


class SocSummary(BaseModel):
    cases_open: int
    cases_total: int
    recent_cases: list[dict[str, Any]]
    live: dict[str, Any] | None
    investigator: dict[str, Any]
    services: dict[str, str]


class LiveControlRequest(BaseModel):
    action: Literal["start", "pause", "resume", "stop", "reset", "advance"]
    mode: Literal["replay", "continuous"] | None = None
    seed: int | None = None
    scenario: str | None = None
    events_per_second: float | None = None
    enable_rules: bool = True
    enable_ml: bool = True


class EvaluationRequest(BaseModel):
    seed: int = 42
    provider: Literal["mock", "haiku"] = "mock"
