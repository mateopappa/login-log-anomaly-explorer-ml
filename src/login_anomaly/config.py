"""Runtime configuration from environment. No secrets are logged or returned to clients."""

from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_HAIKU_MODEL = "claude-haiku-5-5"
CONFIG_VERSION = "mvp-product-v1"


@dataclass(frozen=True)
class Settings:
    database_url: str
    cors_origins: tuple[str, ...]
    investigator_default: str
    anthropic_api_key: str | None
    anthropic_model: str
    config_version: str = CONFIG_VERSION

    @property
    def haiku_configured(self) -> bool:
        return bool(self.anthropic_api_key)


def load_settings() -> Settings:
    origins = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
    key = os.environ.get("ANTHROPIC_API_KEY") or None
    if key is not None:
        key = key.strip() or None
    default = os.environ.get("INVESTIGATOR_DEFAULT", "mock").strip().lower()
    if default not in {"mock", "haiku"}:
        default = "mock"
    return Settings(
        database_url=os.environ.get(
            "DATABASE_URL",
            "sqlite+pysqlite:////tmp/login_anomaly.db",
        ),
        cors_origins=tuple(item.strip() for item in origins.split(",") if item.strip()),
        investigator_default=default,
        anthropic_api_key=key,
        anthropic_model=os.environ.get("ANTHROPIC_MODEL", DEFAULT_HAIKU_MODEL).strip() or DEFAULT_HAIKU_MODEL,
    )
