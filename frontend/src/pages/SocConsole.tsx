import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type DemoPathResponse, type SocSummary, type TrustResponse } from "../api/client";
import { DemoPath } from "../components/DemoPath";
import { TrustPanel } from "../components/TrustPanel";

export function SocConsole() {
  const [searchParams] = useSearchParams();
  const [summary, setSummary] = useState<SocSummary | null>(null);
  const [demo, setDemo] = useState<DemoPathResponse | null>(null);
  const [trust, setTrust] = useState<TrustResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [seed, setSeed] = useState(() => {
    const raw = Number(searchParams.get("seed"));
    return Number.isFinite(raw) && raw >= 0 ? raw : 42;
  });
  const autoSeeded = useRef(false);

  async function load() {
    try {
      setError(null);
      const [sum, demoPath, trustModel] = await Promise.all([api.summary(), api.demoPath(), api.trust()]);
      setSummary(sum);
      setDemo(demoPath);
      setTrust(trustModel);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function seedDemo(nextSeed = seed) {
    setBusy(true);
    try {
      await api.seed(nextSeed);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (autoSeeded.current) return;
    if (searchParams.get("autoseed") !== "1") return;
    autoSeeded.current = true;
    void seedDemo(seed);
  }, [searchParams, seed]);

  const hasCases = (summary?.cases_total ?? 0) > 0;

  return (
    <div>
      <header className="page-header hero-header">
        <div>
          <p className="eyebrow">Login Anomaly Explorer</p>
          <h1>See suspicious logins. Prove the detection.</h1>
          <p>One seed. Five sites. Independent detectors. A bounded investigator.</p>
        </div>
        <div className="hero-actions">
          <label className="seed-field">
            Seed
            <input
              type="number"
              min={0}
              value={seed}
              onChange={(e) => setSeed(Number(e.target.value))}
              disabled={busy}
            />
          </label>
          <button className="btn primary btn-xl" onClick={() => void seedDemo()} disabled={busy}>
            {busy ? "Seeding…" : hasCases ? "Reseed" : "Start demo"}
          </button>
          <Link className="btn btn-xl" to="/pipeline">
            Live streams
          </Link>
          <Link className="btn btn-xl" to="/story">
            Presenter
          </Link>
        </div>
      </header>

      {error && <div className="error">{error}</div>}
      {!summary && !error && <div className="empty">Loading…</div>}

      {summary && (
        <div className="stack">
          <div className="grid metrics">
            <div className="metric">
              <label>Open cases</label>
              <strong>{summary.cases_open}</strong>
            </div>
            <div className="metric">
              <label>Cases</label>
              <strong>{summary.cases_total}</strong>
            </div>
            <div className="metric">
              <label>Investigator</label>
              <strong>{summary.investigator.haiku_configured ? "Haiku" : "Mock"}</strong>
            </div>
            <div className="metric">
              <label>Live</label>
              <strong>{summary.services.live}</strong>
            </div>
          </div>

          {demo && (
            <DemoPath
              pitch={demo.pitch}
              steps={demo.steps}
              talkingPoints={demo.talking_points}
              presenterRoute={demo.presenter_route ?? "/story"}
              primaryAction={{
                label: hasCases ? "Reseed world" : "Seed world",
                onClick: () => void seedDemo(),
                busy,
              }}
            />
          )}

          {trust && <TrustPanel title={trust.title} bullets={trust.bullets} />}

          <section>
            <div className="section-head">
              <h2>Recent cases</h2>
              <Link className="btn btn-lg" to="/cases">
                All cases
              </Link>
            </div>
            {summary.recent_cases.length === 0 ? (
              <div className="empty empty-cta">
                <p>No cases yet.</p>
                <button className="btn primary btn-xl" onClick={() => void seedDemo()} disabled={busy}>
                  {busy ? "Seeding…" : "Start demo"}
                </button>
              </div>
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
