import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type LiveSnapshot, type SocSummary } from "../api/client";

function simLabel(snap: LiveSnapshot | null): string {
  if (!snap) return "—";
  if (!snap.active) return snap.state === "completed" ? "done" : "idle";
  return String(snap.state || "running");
}

export function SocConsole() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [summary, setSummary] = useState<SocSummary | null>(null);
  const [live, setLive] = useState<LiveSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"batch" | "live" | null>(null);
  const [seed, setSeed] = useState(() => {
    const raw = searchParams.get("seed");
    const parsed = raw == null ? Number.NaN : Number(raw);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 42;
  });
  const autoSeeded = useRef(false);

  async function load() {
    try {
      setError(null);
      const [sum, snap] = await Promise.all([api.summary(), api.liveStatus()]);
      setSummary(sum);
      setLive(snap);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void load();
    const id = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(id);
  }, []);

  async function loadBatch(nextSeed = seed) {
    setBusy("batch");
    try {
      await api.seed(nextSeed);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function startLive() {
    setBusy("live");
    try {
      await api.liveControl({
        action: "start",
        mode: "replay",
        seed,
        scenario: "Mixed campaigns",
        events_per_second: 8,
        enable_rules: true,
        enable_ml: true,
      });
      navigate(`/detection?seed=${seed}&autostart=0&rate=8`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(null);
    }
  }

  useEffect(() => {
    if (autoSeeded.current) return;
    if (searchParams.get("autoseed") !== "1") return;
    autoSeeded.current = true;
    void loadBatch(seed);
  }, [searchParams, seed]);

  const hasDataset = Boolean(summary?.active_dataset_id);
  const liveRunning = live?.active === true && (live.state === "running" || live.state === "paused");
  const primaryAction = liveRunning || !hasDataset ? "batch" : "live";
  const investigator = summary?.investigator.haiku_configured ? "Haiku" : "Mock";
  const kindEntries = Object.entries(summary?.cases_by_kind ?? {});

  return (
    <div>
      <header className="page-header">
        <p className="eyebrow">Console</p>
        <h1>Operations</h1>
      </header>

      {error && <div className="error">{error}</div>}
      {!summary && !error && <div className="empty">Loading…</div>}

      {summary && (
        <div className="stack stack-loose">
          <section className="feed-chooser" aria-label="SOC feed mode">
            <p className="eyebrow">Feed the SOC</p>
            <div className="mode-gate">
              <article className={`mode-card ${hasDataset && !liveRunning ? "selected" : ""}`}>
                <p className="eyebrow">Batch</p>
                <h2>Load dataset</h2>
                <p className="muted">
                  ~1800 events into Cases, Scores, and the open queue. End-to-end triage on a fixed seed.
                </p>
                <label className="seed-field">
                  Seed
                  <input
                    type="number"
                    name="seed-batch"
                    min={0}
                    value={seed}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(e) => setSeed(Number(e.target.value))}
                    disabled={busy !== null}
                  />
                </label>
                <button
                  className={`btn btn-xl ${primaryAction === "batch" ? "primary" : ""}`}
                  onClick={() => void loadBatch()}
                  disabled={busy !== null}
                >
                  {busy === "batch" ? "Loading…" : hasDataset ? "Load / Reseed batch" : "Load batch"}
                </button>
              </article>

              <article className={`mode-card ${liveRunning ? "selected" : ""}`}>
                <p className="eyebrow">Live</p>
                <h2>Start session</h2>
                <p className="muted">
                  Replay traffic in Live. Alerts and cases appear as simulated time advances.
                </p>
                <label className="seed-field">
                  Seed
                  <input
                    type="number"
                    name="seed-live"
                    min={0}
                    value={seed}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(e) => setSeed(Number(e.target.value))}
                    disabled={busy !== null}
                  />
                </label>
                <div className="mode-card-actions">
                  <button
                    className={`btn btn-xl ${primaryAction === "live" ? "primary" : ""}`}
                    onClick={() => void startLive()}
                    disabled={busy !== null}
                  >
                    {busy === "live" ? "Starting…" : liveRunning ? "Restart Live" : "Start Live"}
                  </button>
                  {liveRunning && (
                    <Link className="btn btn-xl" to="/detection">
                      Open Live
                    </Link>
                  )}
                </div>
              </article>
            </div>
          </section>

          {(hasDataset || liveRunning) && (
            <>
              <p className="status-line mono">
                {hasDataset ? (
                  <>
                    <span>
                      batch <strong>{summary.active_dataset_id?.slice(0, 16)}…</strong>
                    </span>
                    <span className="status-sep">·</span>
                    <span>
                      seed <strong>{summary.active_seed ?? "—"}</strong>
                    </span>
                    <span className="status-sep">·</span>
                    <span>
                      <strong>{summary.events_total}</strong> events
                    </span>
                  </>
                ) : (
                  <span>No batch loaded</span>
                )}
                <span className="status-sep">·</span>
                <span>sim {simLabel(live)}</span>
                <span className="status-sep">·</span>
                <span>{investigator}</span>
              </p>

              <div className="grid metrics">
                <div className="metric">
                  <label>Open</label>
                  <strong>{summary.cases_open}</strong>
                </div>
                <div className="metric">
                  <label>Cases</label>
                  <strong>{summary.cases_total}</strong>
                </div>
                <div className="metric">
                  <label>Events</label>
                  <strong>{summary.events_total ?? 0}</strong>
                </div>
                <div className="metric">
                  <label>Sim</label>
                  <strong>{simLabel(live)}</strong>
                </div>
              </div>

              {kindEntries.length > 0 && (
                <div className="grid metrics">
                  {kindEntries.map(([kind, count]) => (
                    <div className="metric" key={kind}>
                      <label>{kind}</label>
                      <strong>{count}</strong>
                    </div>
                  ))}
                </div>
              )}

              <section>
                <div className="section-head">
                  <h2>Open queue</h2>
                  <Link className="btn" to="/cases">
                    Cases
                  </Link>
                </div>
                {summary.recent_cases.length === 0 ? (
                  <div className="empty">No open cases in the latest dataset.</div>
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
                            <tr key={id} onClick={() => navigate(`/cases/${id}`)}>
                              <td className="mono">
                                <Link to={`/cases/${id}`}>{id.slice(0, 18)}…</Link>
                              </td>
                              <td>{String(row.kind)}</td>
                              <td>{String(row.priority)}</td>
                              <td>
                                <span className={`badge ${row.verdict ? String(row.verdict) : "inconclusive"}`}>
                                  {row.verdict ? String(row.verdict) : "awaiting"}
                                </span>
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
            </>
          )}
        </div>
      )}
    </div>
  );
}
