import { useEffect, useState } from "react";
import { api, type PipelineStatus } from "../api/client";

export function PipelinePage() {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .pipelineStatus()
      .then(setStatus)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  return (
    <div>
      <header className="page-header">
        <h1>Pipeline & Observability</h1>
        <p>
          Multi-site synthetic AuthEvent streams on a Kafka-compatible broker — the distributed path for the same
          detection product.
        </p>
      </header>

      {error && <div className="error">{error}</div>}
      {!status && !error && <div className="empty">Loading pipeline status…</div>}

      {status && (
        <div className="stack">
          <section className="panel stack">
            <h2 style={{ margin: 0, fontSize: "1rem" }}>{status.title}</h2>
            <p style={{ margin: 0 }}>{status.summary}</p>
            <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
              {status.k8s_narrative}
            </p>
            <div className="toolbar">
              <a className="btn" href={status.observability.grafana_url} target="_blank" rel="noreferrer">
                Grafana
              </a>
              <a className="btn" href={status.observability.prometheus_url} target="_blank" rel="noreferrer">
                Prometheus
              </a>
              <a className="btn" href={status.broker.console_url} target="_blank" rel="noreferrer">
                Redpanda Console
              </a>
              <span className="badge">
                worker: {status.observability.worker_reachable ? "reachable" : "offline (start profile)"}
              </span>
            </div>
          </section>

          <section className="panel stack">
            <h2 style={{ margin: 0, fontSize: "1rem" }}>Broker</h2>
            <p className="muted" style={{ margin: 0 }}>
              {status.broker.kind} · Kafka API{" "}
              <span className="mono">{status.broker.kafka_api}</span> · {status.broker.protocol}
            </p>
            <h3 style={{ margin: "0.5rem 0 0", fontSize: "0.9rem" }}>How to run</h3>
            <ol className="muted" style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.85rem" }}>
              {status.how_to_run.map((step) => (
                <li key={step}>
                  <span className="mono">{step}</span>
                </li>
              ))}
            </ol>
          </section>

          <section>
            <h2 style={{ fontSize: "1rem" }}>Sites / tenants ({status.tenants.length})</h2>
            <p className="muted" style={{ marginTop: 0 }}>
              Each stream is a separate topic. Event and account ids are namespaced so sites share one schema without
              collisions.
            </p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Tenant</th>
                    <th>Region</th>
                    <th>Kind</th>
                    <th>Topic</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {status.tenants.map((tenant) => (
                    <tr key={tenant.tenant_id}>
                      <td>
                        <strong>{tenant.display_name}</strong>
                        <div className="mono muted">{tenant.tenant_id}</div>
                      </td>
                      <td>{tenant.region}</td>
                      <td>
                        <span className="badge">{tenant.kind}</span>
                      </td>
                      <td className="mono">{tenant.topic}</td>
                      <td className="muted" style={{ whiteSpace: "normal" }}>
                        {tenant.description}
                      </td>
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
