"""Multi-tenant synthetic event producer → Kafka-compatible broker (Redpanda)."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Sequence

from login_anomaly.pipeline.metrics import PipelineMetrics
from login_anomaly.pipeline.synthesize import build_tenant_envelopes
from login_anomaly.tenants import TENANTS, Tenant, get_tenant


def _kafka_producer(bootstrap: str):
    from kafka import KafkaProducer  # type: ignore[import-untyped]

    return KafkaProducer(
        bootstrap_servers=bootstrap.split(","),
        acks="all",
        linger_ms=20,
        value_serializer=lambda value: value,
        key_serializer=lambda value: value.encode("utf-8") if value is not None else None,
    )


def publish_once(
    *,
    bootstrap: str,
    tenants: Sequence[Tenant],
    base_seed: int,
    n_events: int,
    metrics: PipelineMetrics | None = None,
) -> dict[str, int]:
    producer = _kafka_producer(bootstrap)
    counts: dict[str, int] = {}
    try:
        for tenant in tenants:
            envelopes = build_tenant_envelopes(tenant, base_seed=base_seed, n_events=n_events)
            for envelope in envelopes:
                producer.send(
                    tenant.topic,
                    key=envelope.event.account_id,
                    value=envelope.to_json_bytes(),
                )
            counts[tenant.tenant_id] = len(envelopes)
            if metrics is not None:
                metrics.record_produced(tenant.tenant_id, len(envelopes))
        producer.flush(timeout=30)
    finally:
        producer.close()
    return counts


def run_loop(
    *,
    bootstrap: str,
    interval_seconds: float,
    base_seed: int,
    n_events: int,
    tenant_ids: Sequence[str] | None = None,
) -> None:
    selected = (
        tuple(get_tenant(tenant_id) for tenant_id in tenant_ids)
        if tenant_ids
        else TENANTS
    )
    metrics = PipelineMetrics()
    cycle = 0
    print(
        f"producer: bootstrap={bootstrap} tenants={len(selected)} "
        f"interval={interval_seconds}s events_per_batch={n_events}",
        flush=True,
    )
    while True:
        seed = base_seed + cycle
        counts = publish_once(
            bootstrap=bootstrap,
            tenants=selected,
            base_seed=seed,
            n_events=n_events,
            metrics=metrics,
        )
        total = sum(counts.values())
        print(f"producer cycle={cycle} published={total} by_tenant={counts}", flush=True)
        cycle += 1
        time.sleep(interval_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish multi-tenant synthetic AuthEvents")
    parser.add_argument(
        "--bootstrap",
        default=os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092"),
    )
    parser.add_argument("--interval", type=float, default=float(os.environ.get("PRODUCER_INTERVAL", "8")))
    parser.add_argument("--seed", type=int, default=int(os.environ.get("PRODUCER_SEED", "42")))
    parser.add_argument("--events", type=int, default=int(os.environ.get("PRODUCER_EVENTS", "120")))
    parser.add_argument(
        "--tenants",
        default=os.environ.get("PRODUCER_TENANTS", ""),
        help="Comma-separated tenant ids (default: all five)",
    )
    parser.add_argument("--once", action="store_true", help="Publish one batch and exit")
    args = parser.parse_args(argv)
    tenant_ids = [part.strip() for part in args.tenants.split(",") if part.strip()] or None
    if args.once:
        selected = (
            tuple(get_tenant(tenant_id) for tenant_id in tenant_ids)
            if tenant_ids
            else TENANTS
        )
        counts = publish_once(
            bootstrap=args.bootstrap,
            tenants=selected,
            base_seed=args.seed,
            n_events=args.events,
        )
        print(counts)
        return 0
    run_loop(
        bootstrap=args.bootstrap,
        interval_seconds=args.interval,
        base_seed=args.seed,
        n_events=args.events,
        tenant_ids=tenant_ids,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
