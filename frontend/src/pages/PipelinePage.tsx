import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type PipelineStatus } from "../api/client";
import { ArchStrip } from "../components/ArchStrip";

export function PipelinePage() {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      setError(null);
      setStatus(await api.pipelineStatus());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void load();
    const id = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(id);
  }, []);

  const live = Boolean(status?.observability.worker_reachable);

  return (
    <div>
      <header className="page-header hero-header">
        <div>
          <p className="eyebrow">Multi-site streams</p>
          <h1>Five producers. One broker. Real detection.</h1>
          <p>Synthetic AuthEvents from HQ + regional sites through Redpanda.</p>
        </div>
        <div className="hero-actions">
          <span className={`pulse-badge ${live ? "on" : "off"}`}>
            <span className="pulse-dot" />
            {live ? "Worker live" : "Worker offline"}
          </span>
          <button className="btn btn-lg" onClick={() => void load()}>
            Refresh
          </button>
          <Link className="btn primary btn-xl" to="/detection">
            Open SOC Live
          </Link>
        </div>
      </header>

      {error && <div className="error">{error}</div>}
      {!status && !error && <div className="empty">Loading…</div>}

      {status && (
        <div className="stack">
          <ArchStrip />
          <div className="cta-row">
            <a className="btn btn-xl" href={status.broker.console_url} target="_blank" rel="noreferrer">
              Redpanda Console
            </a>
            <a className="btn btn-xl" href={status.observability.grafana_url} target="_blank" rel="noreferrer">
              Grafana
            </a>
            <a className="btn btn-xl" href={status.observability.prometheus_url} target="_blank" rel="noreferrer">
              Prometheus
            </a>
          </div>

          {!live && (
            <div className="panel callout">
              <strong>Start streams</strong>
              <code className="mono">docker compose --profile pipeline up -d</code>
            </div>
          )}

          <section>
            <div className="section-head">
              <h2>Sites</h2>
              <span className="muted">{status.tenants.length} topics</span>
            </div>
            <div className="tenant-grid">
              {status.tenants.map((tenant) => (
                <article key={tenant.tenant_id} className={`tenant-card ${live ? "live" : ""}`}>
                  <div className="tenant-card-top">
                    <span className={`pulse-dot ${live ? "on" : ""}`} />
                    <span className="badge">{tenant.kind}</span>
                    <span className="muted">{tenant.region}</span>
                  </div>
                  <strong>{tenant.display_name}</strong>
                  <code className="mono">{tenant.topic}</code>
                </article>
              ))}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
