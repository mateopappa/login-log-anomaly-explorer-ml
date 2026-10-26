import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type PipelineStatus } from "../api/client";
import { PipelineFlow } from "../components/PipelineFlow";

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
          <p className="eyebrow">Pipeline</p>
          <h1>Site feeds</h1>
        </div>
        <div className="hero-actions">
          <button className="btn btn-lg" onClick={() => void load()}>
            Refresh
          </button>
          <Link className="btn primary btn-xl" to="/detection">
            Live
          </Link>
        </div>
      </header>

      {error && <div className="error">{error}</div>}
      {!status && !error && <div className="empty">Loading…</div>}

      {status && (
        <div className="stack stack-loose">
          <PipelineFlow
            workerLive={live}
            links={{
              redpanda: status.broker.console_url,
              grafana: status.observability.grafana_url,
              prometheus: status.observability.prometheus_url,
            }}
          />

          {!live && (
            <p className="muted start-hint">
              Streams offline. In a terminal:{" "}
              <code className="mono">docker compose --profile pipeline up -d</code>
            </p>
          )}

          <section>
            <div className="section-head">
              <h2>Topics</h2>
              <span className="muted">{status.tenants.length}</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Site</th>
                    <th>Region</th>
                    <th>Kind</th>
                    <th>Topic</th>
                  </tr>
                </thead>
                <tbody>
                  {status.tenants.map((tenant) => (
                    <tr key={tenant.tenant_id}>
                      <td>{tenant.display_name}</td>
                      <td>{tenant.region}</td>
                      <td>{tenant.kind}</td>
                      <td className="mono">{tenant.topic}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
