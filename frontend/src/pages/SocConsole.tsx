import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type LiveSnapshot, type SocSummary } from "../api/client";

function simLabel(snap: LiveSnapshot | null): string {
  if (!snap) return "—";
  if (!snap.active) return snap.state === "completed" ? "done" : "idle";
  return String(snap.state || "running");
}

export function SocConsole() {
  const [searchParams] = useSearchParams();
  const [summary, setSummary] = useState<SocSummary | null>(null);
  const [live, setLive] = useState<LiveSnapshot | null>(null);
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
  const investigator = summary?.investigator.haiku_configured ? "Haiku" : "Mock";

  return (
    <div>
      <header className="page-header hero-header">
        <div>
          <p className="eyebrow">Console</p>
          <h1>Operations</h1>
        </div>
        <div className="hero-actions">
          <label className="seed-field">
            Seed
            <input
              type="number"
              name="seed"
              min={0}
              value={seed}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setSeed(Number(e.target.value))}
              disabled={busy}
            />
          </label>
          <button className="btn primary btn-xl" onClick={() => void seedDemo()} disabled={busy}>
            {busy ? "Loading…" : hasCases ? "Reseed" : "Load"}
          </button>
        </div>
      </header>

      {error && <div className="error">{error}</div>}
      {!summary && !error && <div className="empty">Loading…</div>}

      {summary && (
        <div className="stack stack-loose">
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
              <label>Investigator</label>
              <strong>{investigator}</strong>
            </div>
            <div className="metric">
              <label>Sim</label>
              <strong>{simLabel(live)}</strong>
            </div>
          </div>

          <div className="ops-actions">
            {hasCases ? (
              <>
                <Link className="btn primary btn-xl" to="/cases">
                  Cases
                </Link>
                <Link className="btn btn-xl" to="/detection">
                  Live
                </Link>
              </>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                No cases. Load a dataset, then open Cases or Live.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
