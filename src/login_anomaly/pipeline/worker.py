"""Consume the five site streams, detect, and write cases for the SOC console.

Each finished publish is one site batch. Rules and ML run on that batch, the
correlator builds cases, and the mock investigator writes a run. Metrics stay
on this process. Set DATABASE_URL or the batch is counted and not stored.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from login_anomaly.detection.rules import detect
from login_anomaly.events import AuthEvent
from login_anomaly.pipeline.envelope import StreamEnvelope
from login_anomaly.pipeline.http_metrics import start_metrics_server
from login_anomaly.pipeline.metrics import PipelineMetrics
from login_anomaly.tenants import TENANTS


@dataclass
class TopicBatch:
    """One producer publish. `produced_at_utc` changes on the next publish."""

    produced_at: datetime | None = None
    events: list[AuthEvent] = field(default_factory=list)
    envelopes: list[StreamEnvelope] = field(default_factory=list)
    counted: int = 0
    # The publish that just closed. The consumer persists it, then clears this.
    ready: list[StreamEnvelope] = field(default_factory=list)


def process_batch(
    *,
    tenant_id: str,
    events: Sequence[AuthEvent],
    metrics: PipelineMetrics,
) -> int:
    """Run rule detection on a buffered batch. Returns alert count. Testable without Kafka."""
    if not events:
        return 0
    alerts = detect(tuple(events))
    if alerts:
        metrics.record_alert(tenant_id, len(alerts))
    return len(alerts)


def handle_raw_message(
    *,
    raw: bytes,
    buffers: dict[str, TopicBatch],
    metrics: PipelineMetrics,
) -> int | None:
    """Detect on the whole publish, not a 25-event slice.

    shortcut: the alert counter only goes up, so a rule that stops firing is not subtracted.
    """
    try:
        payload = json.loads(raw.decode("utf-8"))
        envelope = StreamEnvelope.from_dict(payload)
    except Exception:  # noqa: BLE001 — keep consuming on bad messages
        metrics.record_decode_error()
        return None

    metrics.record_consumed(envelope.tenant_id)
    batch = buffers.setdefault(envelope.topic, TopicBatch())
    if batch.produced_at is not None and batch.produced_at != envelope.produced_at_utc:
        batch.ready = list(batch.envelopes)
        batch.envelopes.clear()
        batch.events.clear()
        batch.counted = 0
    batch.produced_at = envelope.produced_at_utc
    batch.envelopes.append(envelope)
    batch.events.append(envelope.event)
    current = len(detect(tuple(batch.events)))
    new = current - batch.counted
    if new > 0:
        metrics.record_alert(envelope.tenant_id, new)
        batch.counted = current
    return new


_MODEL: object | None = None
_DB_READY = False


def _persist_site_batch(envelopes: list[StreamEnvelope]) -> None:
    """Store one finished publish. Without DATABASE_URL the metrics path still runs."""
    url = os.environ.get("DATABASE_URL")
    if not url or not envelopes:
        return
    global _MODEL, _DB_READY
    try:
        from login_anomaly.persistence.db import init_db, session_scope
        from login_anomaly.pipeline.ingest import persist_site_envelopes

        if _MODEL is None:
            from login_anomaly.evaluation.experiment import train_baseline

            _MODEL = train_baseline()[0]
        if not _DB_READY:
            init_db(url)
            _DB_READY = True
        with session_scope(url) as session:
            result = persist_site_envelopes(session, envelopes, _MODEL)
        print(
            f"worker: stored tenant={result['tenant_id']} cases={result['cases']} events={result['events']}",
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001 — keep consuming if the queue write fails
        print(f"worker: site batch not stored: {exc}", flush=True)


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
    buffers: dict[str, TopicBatch] = {}

    try:
        for message in consumer:
            count = handle_raw_message(
                raw=message.value,
                buffers=buffers,
                metrics=metrics,
            )
            for batch in buffers.values():
                if batch.ready:
                    _persist_site_batch(batch.ready)
                    batch.ready = []
            if count:
                print(
                    f"worker: flushed rule_alerts={count}",
                    flush=True,
                )
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
