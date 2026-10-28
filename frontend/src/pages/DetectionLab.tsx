import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type LiveSnapshot } from "../api/client";
import { LiveRunPanel } from "../components/LiveRunPanel";
import { SessionFlow } from "../components/SessionFlow";

const TICK_MS = 1000;

export function DetectionLab() {
  const [searchParams] = useSearchParams();
  const [snap, setSnap] = useState<LiveSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<"replay" | "continuous">("replay");
  const [scenario, setScenario] = useState("Mixed campaigns");
  const [seed, setSeed] = useState(() => {
    const raw = searchParams.get("seed");
    const parsed = raw == null ? Number.NaN : Number(raw);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 42;
  });
  const [rate, setRate] = useState(() => {
    const raw = Number(searchParams.get("rate"));
    return Number.isFinite(raw) ? Math.min(50, Math.max(1, raw)) : 8;
  });
  const autoStarted = useRef(false);

  const apply = useCallback((data: LiveSnapshot) => {
    setSnap(data);
  }, []);

  async function refresh() {
    apply(await api.liveStatus());
  }

  // Poll snapshot for UI; Layout owns advance ticks while state === running.
  useEffect(() => {
    void refresh().catch((err) => setError(err instanceof Error ? err.message : String(err)));
    const id = window.setInterval(() => {
      void api
        .liveStatus()
        .then(apply)
        .catch((err) => setError(err instanceof Error ? err.message : String(err)));
    }, TICK_MS);
    return () => window.clearInterval(id);
  }, [apply]);

  async function control(action: string, extra: Record<string, unknown> = {}) {
    setBusy(true);
    setError(null);
    try {
      const result = await api.liveControl({ action, ...extra });
      apply(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (autoStarted.current) return;
    if (searchParams.get("autostart") !== "1") return;
    if (snap == null) return;
    if (snap.active && snap.state === "running") return;
    autoStarted.current = true;
    void control("start", {
      mode,
      seed,
      scenario: mode === "replay" ? scenario : undefined,
      events_per_second: rate,
      enable_rules: true,
      enable_ml: true,
    });
  }, [searchParams, snap, mode, seed, scenario, rate]);

  const summary = snap?.summary;
  const running = snap?.state === "running";
  const scenarios = snap?.scenarios?.length ? snap.scenarios : ["Mixed campaigns"];

  return (
    <div className="stack">
      <header className="page-header hero-header">
        <div>
          <p className="eyebrow">Live</p>
          <h1>Live session</h1>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="panel stack">
        <h2 style={{ margin: 0, fontSize: "1rem" }}>Session setup</h2>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <label className="muted">
            Mode{" "}
            <select value={mode} onChange={(e) => setMode(e.target.value as "replay" | "continuous")} disabled={busy || running}>
              <option value="replay">Replay (fixed scenario)</option>
              <option value="continuous">Continuous (chunked)</option>
            </select>
          </label>
          {mode === "replay" && (
            <label className="muted">
              Scenario{" "}
              <select value={scenario} onChange={(e) => setScenario(e.target.value)} disabled={busy || running}>
                {scenarios.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
          )}
          {mode === "replay" && scenario === "Boundary lab" && (
            <p className="muted" style={{ margin: 0 }}>
              Campaigns sit just outside the rule thresholds, with benign look-alikes. The queue is what the rule did not close.
            </p>
          )}
          <label className="muted">
            Seed{" "}
            <input
              type="number"
              value={seed}
              min={0}
              style={{ width: "6rem" }}
              disabled={busy || running}
              onChange={(e) => setSeed(Number(e.target.value))}
            />
          </label>
          <label className="muted">
            Rate{" "}
            <input
              type="number"
              value={rate}
              min={1}
              max={50}
              style={{ width: "4rem" }}
              disabled={busy || running}
              onChange={(e) => {
                const next = Number(e.target.value);
                if (Number.isFinite(next)) setRate(Math.min(50, Math.max(1, next)));
              }}
            />{" "}
            evt/s
          </label>
        </div>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <button
            className="btn primary"
            disabled={busy}
            onClick={() =>
              void control("start", {
                mode,
                seed,
                scenario: mode === "replay" ? scenario : undefined,
                events_per_second: rate,
                enable_rules: true,
                enable_ml: true,
              })
            }
          >
            Start
          </button>
          <button className="btn" disabled={busy || !running} onClick={() => void control("advance")}>
            Advance once
          </button>
          <button
            className="btn"
            disabled={busy || snap?.state !== "running"}
            onClick={() => void control("pause")}
          >
            Pause
          </button>
          <button
            className="btn"
            disabled={busy || snap?.state !== "paused"}
            onClick={() => void control("resume")}
          >
            Resume
          </button>
          <button className="btn" disabled={busy || !snap?.active} onClick={() => void control("stop")}>
            Stop
          </button>
          <button className="btn" disabled={busy} onClick={() => void control("reset")}>
            Reset
          </button>
          <button className="btn" disabled={busy} onClick={() => void refresh()}>
            Refresh
          </button>
        </div>
        <p className="muted" style={{ margin: 0 }}>
          {snap?.message ?? "No live session yet."}
          {running
            ? " · advancing every 1s (keeps going if you leave this tab)"
            : snap?.state === "paused"
              ? " · paused — Resume to keep advancing"
              : ""}
        </p>
      </section>

      <div className="grid metrics">
        <div className="metric">
          <label>State</label>
          <strong>{snap?.state ?? "idle"}</strong>
        </div>
        <div className="metric">
          <label>Released</label>
          <strong>
            {summary ? `${summary.released}/${summary.generated || "∞"}` : "—"}
          </strong>
        </div>
        <div className="metric">
          <label>Rule alerts</label>
          <strong>{summary?.rule_alerts ?? "—"}</strong>
        </div>
        <div className="metric">
          <label>Cases open</label>
          <strong>{summary?.cases_open ?? "—"}</strong>
        </div>
        <div className="metric">
          <label>Investigations</label>
          <strong>{summary?.investigations_completed ?? "—"}</strong>
        </div>
        <div className="metric">
          <label>Simulated time</label>
          <strong style={{ fontSize: "0.95rem" }}>{summary?.simulated_time?.slice(0, 19) ?? "—"}</strong>
        </div>
      </div>

      {snap?.active && <LiveRunPanel />}

      <SessionFlow
        events={snap?.recent_events ?? []}
        alerts={snap?.alerts ?? []}
        running={running}
      />

      <section className="panel">
        <div className="section-head">
          <div>
            <p className="eyebrow">This session only</p>
            <h2 style={{ margin: 0, fontSize: "1rem" }}>Triage queue</h2>
          </div>
          <Link className="btn" to="/cases?scope=live">
            Cases queue
          </Link>
        </div>
        <p className="muted" style={{ margin: 0 }}>
          Detectors file the case and a priority. Nothing is investigated until you open the dossier.
        </p>
        {(snap?.cases?.length ?? 0) === 0 ? (
          <div className="empty">Flagged cases land here after detectors fire. Open one to investigate.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Case</th>
                  <th>Kind</th>
                  <th>Priority</th>
                  <th>Verdict</th>
                  <th>Review</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {snap!.cases.map((row) => {
                  const id = String(row.case_id);
                  return (
                    <tr key={id}>
                      <td className="mono">
                        <Link to={`/cases/${encodeURIComponent(id)}`}>{id.slice(0, 18)}…</Link>
                      </td>
                      <td>{String(row.kind)}</td>
                      <td>{String(row.priority)}</td>
                      <td>
                        <span className={`badge ${row.verdict === "not investigated" ? "inconclusive" : String(row.verdict)}`}>
                          {row.verdict === "not investigated" ? "awaiting" : String(row.verdict)}
                        </span>
                      </td>
                      <td>{row.review === "not reviewed" ? "—" : String(row.review)}</td>
                      <td>{String(row.status)}</td>
                      <td>
                        <Link className="btn" to={`/cases/${encodeURIComponent(id)}`}>
                          Investigate
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
