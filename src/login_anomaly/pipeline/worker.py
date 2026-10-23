"""Consume multi-tenant auth streams, run rule detection, expose Prometheus metrics."""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Sequence

from login_anomaly.detection.rules import detect
from login_anomaly.pipeline.envelope import StreamEnvelope
from login_anomaly.pipeline.metrics import PipelineMetrics
from login_anomaly.tenants import TENANTS


def _start_metrics_server(port: int) -> None:
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    except ImportError:
        print("worker: prometheus_client missing; /metrics disabled", flush=True)
        return

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path not in {"/metrics", "/healthz"}:
                self.send_response(404)
                self.end_headers()
                return
            if self.path == "/healthz":
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            payload = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    server = HTTPServer(("0.0.0.0", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"worker: metrics on :{port}/metrics", flush=True)


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
    _start_metrics_server(args.metrics_port)
    topics = [tenant.topic for tenant in TENANTS]
    run_consumer(bootstrap=args.bootstrap, group_id=args.group, topics=topics, metrics=metrics)
    return 0


if __name__ == "__main__":
    sys.exit(main())
