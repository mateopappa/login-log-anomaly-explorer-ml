"""Worker detection path without a live Redpanda broker."""

from __future__ import annotations

import json

from login_anomaly.pipeline.metrics import PipelineMetrics
from login_anomaly.pipeline.synthesize import build_tenant_envelopes
from login_anomaly.pipeline.worker import handle_raw_message, process_batch
from login_anomaly.tenants import get_tenant


def test_process_batch_records_rule_alerts() -> None:
    tenant = get_tenant("acme-hq")
    envelopes = build_tenant_envelopes(tenant, base_seed=42, n_events=80, n_accounts=20)
    metrics = PipelineMetrics()
    events = [item.event for item in envelopes]
    alert_count = process_batch(tenant_id=tenant.tenant_id, events=events, metrics=metrics)
    assert alert_count >= 0
    assert metrics.rule_alerts == alert_count


def test_handle_raw_message_decode_error_and_flush() -> None:
    tenant = get_tenant("contoso-jp")
    envelopes = build_tenant_envelopes(tenant, base_seed=3, n_events=80, n_accounts=20)
    metrics = PipelineMetrics()
    buffers: dict[str, list] = {}

    bad = handle_raw_message(raw=b"not-json", buffers=buffers, metrics=metrics, flush_every=5)
    assert bad is None
    assert metrics.decode_errors == 1

    flushed = None
    for envelope in envelopes[:5]:
        flushed = handle_raw_message(
            raw=json.dumps(envelope.to_dict()).encode("utf-8"),
            buffers=buffers,
            metrics=metrics,
            flush_every=5,
        )
    assert metrics.events_consumed == 5
    assert flushed is not None  # fifth message triggers flush
    assert buffers[tenant.topic] == []
