"""Kafka message envelope: tenant metadata + AuthEvent payload.

AuthEvent itself stays tenant-agnostic. Tenant identity lives on the envelope
and in namespaced identifiers so multi-site streams share one schema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.tenants import Tenant


@dataclass(frozen=True)
class StreamEnvelope:
    tenant_id: str
    display_name: str
    region: str
    topic: str
    produced_at_utc: datetime
    event: AuthEvent
    # Generator provenance so a finished publish can be scored later. Not labels.
    seed: int | None = None
    n_events: int | None = None
    n_accounts: int | None = None
    duration_hours: int | None = None

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
            "region": self.region,
            "topic": self.topic,
            "produced_at_utc": self.produced_at_utc.isoformat().replace("+00:00", "Z"),
            "event": event_to_payload(self.event),
            "seed": self.seed,
            "n_events": self.n_events,
            "n_accounts": self.n_accounts,
            "duration_hours": self.duration_hours,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> StreamEnvelope:
        event_payload = payload["event"]
        produced = payload["produced_at_utc"]
        if isinstance(produced, str):
            produced_at = datetime.fromisoformat(produced.replace("Z", "+00:00"))
        else:
            raise TypeError("produced_at_utc must be an ISO-8601 string")
        return cls(
            tenant_id=str(payload["tenant_id"]),
            display_name=str(payload["display_name"]),
            region=str(payload["region"]),
            topic=str(payload["topic"]),
            produced_at_utc=produced_at,
            seed=_optional_int(payload.get("seed")),
            n_events=_optional_int(payload.get("n_events")),
            n_accounts=_optional_int(payload.get("n_accounts")),
            duration_hours=_optional_int(payload.get("duration_hours")),
            event=AuthEvent(
                event_id=str(event_payload["event_id"]),
                timestamp_utc=datetime.fromisoformat(
                    str(event_payload["timestamp_utc"]).replace("Z", "+00:00")
                ),
                account_id=str(event_payload["account_id"]),
                source_ip=str(event_payload["source_ip"]),
                outcome=Outcome(str(event_payload["outcome"])),
                country_code=str(event_payload["country_code"]),
            ),
        )


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(value)


def event_to_payload(event: AuthEvent) -> dict[str, str]:
    return {
        "event_id": event.event_id,
        "timestamp_utc": event.timestamp_utc.isoformat().replace("+00:00", "Z"),
        "account_id": event.account_id,
        "source_ip": event.source_ip,
        "outcome": event.outcome.value,
        "country_code": event.country_code,
    }


def namespace_event(event: AuthEvent, tenant: Tenant) -> AuthEvent:
    """Prefix ids so five sites can share one broker without collisions."""
    prefix = tenant.tenant_id
    return AuthEvent(
        event_id=_clip_id(f"{prefix}-{event.event_id}"),
        timestamp_utc=event.timestamp_utc,
        account_id=_clip_id(f"{prefix}-{event.account_id}"),
        source_ip=event.source_ip,
        outcome=event.outcome,
        country_code=event.country_code,
    )


def _clip_id(value: str) -> str:
    if len(value) <= 64:
        return value
    return value[:64]
