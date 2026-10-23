"""Consume multi-tenant auth streams, run rule detection, expose Prometheus metrics."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from login_anomaly.detection.rules import detect
from login_anomaly.pipeline.envelope import StreamEnvelope
from login_anomaly.pipeline.http_metrics import start_metrics_server
from login_anomaly.pipeline.metrics import PipelineMetrics
from login_anomaly.tenants import TENANTS


def run_consumer(
    *,
    bootstrap: str,
    group_id: str,
    topics: Sequence[str],
    metrics: PipelineMetrics,
) -> None:
    from kafka import KafkaConsumer  # type: ignore[import-untyped]

    consumer = KafkaConsumer(
        *topics,
        bootstrap_servers=bootstrap.split(","),
        group_id=group_id,
        enable_auto_commit=True,
        auto_offset_reset="earliest",
        value_deserializer=lambda raw: raw,
    )
    print(f"worker: consuming topics={list(topics)} group={group_id}", flush=True)
    buffers: dict[str, list] = {topic: [] for topic in topics}
    flush_every = 25

    try:
        for message in consumer:
            try:
                payload = json.loads(message.value.decode("utf-8"))
                envelope = StreamEnvelope.from_dict(payload)
            except Exception as exc:  # noqa: BLE001 — keep consuming on bad messages
                metrics.record_decode_error()
                print(f"worker: decode error: {exc}", flush=True)
                continue

            metrics.record_consumed(envelope.tenant_id)
            buffers.setdefault(envelope.topic, []).append(envelope.event)
            bucket = buffers[envelope.topic]
            if len(bucket) >= flush_every:
                alerts = detect(tuple(bucket))
                if alerts:
                    metrics.record_alert(envelope.tenant_id, len(alerts))
                    print(
                        f"worker: tenant={envelope.tenant_id} batch={len(bucket)} "
                        f"rule_alerts={len(alerts)}",
                        flush=True,
                    )
                buffers[envelope.topic] = []
    finally:
        consumer.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consume auth event streams and detect")
    parser.add_argument(
        "--bootstrap",
        default=os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092"),
    )
    parser.add_argument("--group", default=os.environ.get("KAFKA_GROUP", "login-anomaly-worker"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9100")))
    args = parser.parse_args(argv)

    metrics = PipelineMetrics()
    start_metrics_server(args.metrics_port, label="worker")
    topics = [tenant.topic for tenant in TENANTS]
    run_consumer(bootstrap=args.bootstrap, group_id=args.group, topics=topics, metrics=metrics)
    return 0


if __name__ == "__main__":
    sys.exit(main())
