"""Build namespaced AuthEvents for one tenant stream."""

from __future__ import annotations

from datetime import datetime, timezone

from login_anomaly.events import AuthEvent
from login_anomaly.pipeline.envelope import StreamEnvelope, namespace_event
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate
from login_anomaly.simulation.scenarios import ScenarioPlan
from login_anomaly.tenants import Tenant


# Same plan for every site publish. Evaluation rebuilds labels from this plan plus the seed.
SITE_PLAN = ScenarioPlan(
    bruteforce_campaigns=1,
    password_spraying_campaigns=1,
    impossible_travel_campaigns=1,
    benign_travelers=1,
)
SITE_START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def build_tenant_envelopes(
    tenant: Tenant,
    *,
    base_seed: int = 42,
    n_events: int = 120,
    n_accounts: int = 30,
    duration_hours: int = 72,
) -> list[StreamEnvelope]:
    """Generate a small deterministic batch for one site/subsidiary.

    Batches stay large enough for one nominal campaign set (bruteforce + spray
    + travel) so the rule detector has something to fire on in the worker.
    """
    plan = SITE_PLAN
    seed = base_seed + tenant.seed_offset
    config = GeneratorConfig(
        seed=seed,
        start_utc=SITE_START,
        duration_hours=duration_hours,
        n_accounts=n_accounts,
        n_events=n_events,
    )
    dataset = generate(config, plan)
    now = datetime.now(tz=timezone.utc)
    envelopes: list[StreamEnvelope] = []
    for event in dataset.events:
        namespaced = namespace_event(event, tenant)
        envelopes.append(
            StreamEnvelope(
                tenant_id=tenant.tenant_id,
                display_name=tenant.display_name,
                region=tenant.region,
                topic=tenant.topic,
                produced_at_utc=now,
                event=namespaced,
                seed=seed,
                n_events=n_events,
                n_accounts=n_accounts,
                duration_hours=duration_hours,
            )
        )
    return envelopes


def events_from_envelopes(envelopes: list[StreamEnvelope]) -> list[AuthEvent]:
    return [item.event for item in envelopes]
