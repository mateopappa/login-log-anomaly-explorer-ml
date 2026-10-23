"""Prometheus metrics for the stream worker (optional prometheus_client)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PipelineMetrics:
    """In-process counters; also exported when prometheus_client is installed."""

    events_consumed: int = 0
    events_produced: int = 0
    rule_alerts: int = 0
    decode_errors: int = 0
    by_tenant: dict[str, int] = field(default_factory=dict)
    _prom: object | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        try:
            from prometheus_client import Counter
        except ImportError:
            return
        consumed = Counter(
            "login_anomaly_events_consumed_total",
            "Auth events consumed from the broker",
            ["tenant_id"],
        )
        produced = Counter(
            "login_anomaly_events_produced_total",
            "Auth events produced to the broker",
            ["tenant_id"],
        )
        alerts = Counter(
            "login_anomaly_rule_alerts_total",
            "Rule alerts raised by the stream worker",
            ["tenant_id"],
        )
        errors = Counter(
            "login_anomaly_decode_errors_total",
            "Envelope decode failures",
        )
        self._prom = {"consumed": consumed, "produced": produced, "alerts": alerts, "errors": errors}

    def record_produced(self, tenant_id: str, count: int = 1) -> None:
        self.events_produced += count
        self.by_tenant[tenant_id] = self.by_tenant.get(tenant_id, 0) + count
        prom = self._prom
        if isinstance(prom, dict):
            prom["produced"].labels(tenant_id=tenant_id).inc(count)

    def record_consumed(self, tenant_id: str, count: int = 1) -> None:
        self.events_consumed += count
        self.by_tenant[tenant_id] = self.by_tenant.get(tenant_id, 0) + count
        prom = self._prom
        if isinstance(prom, dict):
            prom["consumed"].labels(tenant_id=tenant_id).inc(count)

    def record_alert(self, tenant_id: str, count: int = 1) -> None:
        self.rule_alerts += count
        prom = self._prom
        if isinstance(prom, dict):
            prom["alerts"].labels(tenant_id=tenant_id).inc(count)

    def record_decode_error(self) -> None:
        self.decode_errors += 1
        prom = self._prom
        if isinstance(prom, dict):
            prom["errors"].inc()

    def snapshot(self) -> dict[str, object]:
        return {
            "events_consumed": self.events_consumed,
            "events_produced": self.events_produced,
            "rule_alerts": self.rule_alerts,
            "decode_errors": self.decode_errors,
            "by_tenant": dict(self.by_tenant),
        }
