"""Resolve investigator providers from configuration without exposing secrets."""

from __future__ import annotations

from login_anomaly.agentic.haiku_provider import HaikuInvestigatorProvider
from login_anomaly.agentic.provider import InvestigatorProvider, MockInvestigatorProvider
from login_anomaly.config import Settings


def resolve_provider(settings: Settings, requested: str | None = None) -> InvestigatorProvider:
    choice = (requested or settings.investigator_default).strip().lower()
    if choice in {"mock", "deterministic"}:
        return MockInvestigatorProvider()
    if choice in {"haiku", "llm", "anthropic"}:
        if not settings.haiku_configured:
            raise LookupError("Claude Haiku is not configured (set ANTHROPIC_API_KEY)")
        return HaikuInvestigatorProvider(api_key=settings.anthropic_api_key, model=settings.anthropic_model)
    raise ValueError(f"unknown investigator provider: {choice!r}")


def provider_status(settings: Settings) -> dict[str, object]:
    return {
        "default": settings.investigator_default,
        "mock_available": True,
        "haiku_configured": settings.haiku_configured,
        "haiku_model": settings.anthropic_model if settings.haiku_configured else None,
        "config_version": settings.config_version,
    }
