"""Worker detection path without a live Redpanda broker."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from login_anomaly.detection.rules import detect
from login_anomaly.pipeline.metrics import PipelineMetrics
from login_anomaly.pipeline.synthesize import build_tenant_envelopes
from login_anomaly.pipeline.worker import TopicBatch, handle_raw_message, process_batch
from login_anomaly.tenants import get_tenant


def _feed(envelopes, metrics: PipelineMetrics, buffers: dict[str, TopicBatch]) -> None:
    for envelope in envelopes:
        handle_raw_message(
            raw=json.dumps(envelope.to_dict()).encode("utf-8"),
            buffers=buffers,
            metrics=metrics,
        )


def test_process_batch_records_rule_alerts() -> None:
    tenant = get_tenant("acme-hq")
    envelopes = build_tenant_envelopes(tenant, base_seed=42, n_events=80, n_accounts=20)
    metrics = PipelineMetrics()
    events = [item.event for item in envelopes]
    alert_count = process_batch(tenant_id=tenant.tenant_id, events=events, metrics=metrics)
    assert alert_count == len(detect(tuple(events)))
    assert metrics.rule_alerts == alert_count


def test_handle_raw_message_matches_full_batch() -> None:
    tenant = get_tenant("acme-hq")
    envelopes = build_tenant_envelopes(tenant, base_seed=42, n_events=80, n_accounts=20)
    metrics = PipelineMetrics()
    buffers: dict[str, TopicBatch] = {}
    _feed(envelopes, metrics, buffers)
    events = [item.event for item in envelopes]
    assert metrics.events_consumed == len(envelopes)
    assert metrics.rule_alerts == len(detect(tuple(events)))
    assert len(buffers[tenant.topic].events) == len(events)


def test_next_publish_does_not_keep_the_previous_batch() -> None:
    tenant = get_tenant("acme-hq")
    first = build_tenant_envelopes(tenant, base_seed=42, n_events=80, n_accounts=20)
    later = datetime.now(timezone.utc) + timedelta(minutes=5)
    second = [replace(item, produced_at_utc=later) for item in first]
    metrics = PipelineMetrics()
    buffers: dict[str, TopicBatch] = {}
    _feed(first, metrics, buffers)
    _feed(second, metrics, buffers)
    ready = buffers[tenant.topic].ready
    assert len(ready) == len(first)
    assert ready[0].seed == first[0].seed
    assert len(buffers[tenant.topic].events) == len(second)
    assert metrics.rule_alerts == len(detect(tuple(item.event for item in first))) + len(
        detect(tuple(item.event for item in second))
    )


def test_handle_raw_message_decode_error() -> None:
    metrics = PipelineMetrics()
    buffers: dict[str, TopicBatch] = {}
    bad = handle_raw_message(raw=b"not-json", buffers=buffers, metrics=metrics)
    assert bad is None
    assert metrics.decode_errors == 1
    assert buffers == {}
