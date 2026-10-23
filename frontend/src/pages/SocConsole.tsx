import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type DataExplainer, type DemoPathResponse, type SocSummary, type TrustResponse } from "../api/client";
import { DemoPath } from "../components/DemoPath";
import { TrustPanel } from "../components/TrustPanel";

export function SocConsole() {
  const [summary, setSummary] = useState<SocSummary | null>(null);
  const [explainer, setExplainer] = useState<DataExplainer | null>(null);
  const [demo, setDemo] = useState<DemoPathResponse | null>(null);
  const [trust, setTrust] = useState<TrustResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [seed, setSeed] = useState(42);

  async function load() {
    try {
      setError(null);
      const [sum, data, demoPath, trustModel] = await Promise.all([
        api.summary(),
        api.dataExplainer(),
        api.demoPath(),
        api.trust(),
      ]);
      setSummary(sum);
      setExplainer(data);
      setDemo(demoPath);
      setTrust(trustModel);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function seedDemo() {
    setBusy(true);
    try {
      await api.seed(seed);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <header className="page-header">
        <h1>SOC Console</h1>
        <p>
          Product home: seed a reproducible world, walk the demo path, then triage cases — with multi-site streaming
          available when you need the distributed story.
        </p>
      </header>

      <div className="toolbar">
        <label className="muted">
          Seed{" "}
          <input
            type="number"
            min={0}
            value={seed}
            style={{ width: "6rem" }}
            onChange={(e) => setSeed(Number(e.target.value))}
            disabled={busy}
          />
        </label>
        <button className="btn primary" onClick={() => void seedDemo()} disabled={busy}>
          {busy ? "Seeding…" : "Seed demo dataset"}
        </button>
        <button className="btn" onClick={() => void load()}>
          Refresh
        </button>
        <Link className="btn" to="/detection">
          Open SOC Live
        </Link>
        <Link className="btn" to="/pipeline">
          Multi-site pipeline
        </Link>
      </div>

      {error && <div className="error">{error}</div>}

      {!summary && !error && <div className="empty">Loading console…</div>}

      {summary && (
        <div className="stack">
          <div className="grid metrics">
            <div className="metric">
              <label>Open cases</label>
              <strong>{summary.cases_open}</strong>
            </div>
            <div className="metric">
              <label>Total cases</label>
              <strong>{summary.cases_total}</strong>
            </div>
            <div className="metric">
              <label>Live</label>
              <strong>{summary.services.live}</strong>
            </div>
            <div className="metric">
              <label>Investigator</label>
              <strong>{summary.investigator.haiku_configured ? "Haiku ready" : "Mock only"}</strong>
            </div>
          </div>

          {demo && (
            <DemoPath pitch={demo.pitch} steps={demo.steps} talkingPoints={demo.talking_points} />
          )}

          {trust && <TrustPanel title={trust.title} bullets={trust.bullets} />}

          {explainer && (
            <section className="panel stack">
              <h2 style={{ margin: 0, fontSize: "1rem" }}>{explainer.title}</h2>
              <p style={{ margin: 0 }}>{explainer.summary}</p>
              <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))" }}>
                {explainer.campaign_types.map((item) => (
                  <div key={item.id} style={{ borderTop: "1px solid var(--border)", paddingTop: "0.75rem" }}>
                    <strong>{item.name}</strong>
                    <p className="muted" style={{ margin: "0.35rem 0 0", fontSize: "0.85rem" }}>
                      {item.description}
                    </p>
                  </div>
                ))}
              </div>
              <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
                Seed demo defaults: {explainer.seed_demo_defaults.n_events} events ·{" "}
                {explainer.seed_demo_defaults.n_accounts} accounts · {explainer.seed_demo_defaults.duration_hours}h ·
                campaigns bf/sp/travel/benign = {explainer.seed_demo_defaults.bruteforce_campaigns}/
                {explainer.seed_demo_defaults.password_spraying_campaigns}/
                {explainer.seed_demo_defaults.impossible_travel_campaigns}/
                {explainer.seed_demo_defaults.benign_travelers}. Same seed → same dataset.
              </p>
              <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
                <strong>Seed demo</strong> persists a batch for Cases. <strong>SOC Live</strong> streams events in
                process — use Detection Lab to watch release → detect → case → investigate.
              </p>
              <ol className="muted" style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.85rem" }}>
                {explainer.pipeline.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </section>
          )}

          <section className="panel">
            <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Service status</h2>
            <p className="muted" style={{ marginTop: 0 }}>
              Default provider: <span className="mono">{summary.investigator.default}</span>
              {summary.investigator.haiku_configured
                ? ` · Haiku model ${summary.investigator.haiku_model}`
                : " · set ANTHROPIC_API_KEY to enable Claude Haiku"}
            </p>
            <div className="toolbar">
              {Object.entries(summary.services).map(([name, value]) => (
                <span key={name} className="badge">
                  {name}: {value}
                </span>
              ))}
            </div>
          </section>

          <section>
            <h2 style={{ fontSize: "1rem" }}>Recent cases</h2>
            {summary.recent_cases.length === 0 ? (
              <div className="empty">No cases yet. Seed a demo dataset to populate the console.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Case</th>
                      <th>Kind</th>
                      <th>Priority</th>
                      <th>Verdict</th>
                      <th>Mode</th>
                      <th>Review</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.recent_cases.map((row) => {
                      const id = String(row.case_id);
                      return (
                        <tr key={id}>
                          <td className="mono">
                            <Link to={`/cases/${id}`}>{id.slice(0, 18)}…</Link>
                          </td>
                          <td>{String(row.kind)}</td>
                          <td>{String(row.priority)}</td>
                          <td>
                            <span className={`badge ${String(row.verdict ?? "")}`}>{String(row.verdict ?? "—")}</span>
                          </td>
                          <td>{String(row.mode ?? "—")}</td>
                          <td>{String(row.review ?? "—")}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
