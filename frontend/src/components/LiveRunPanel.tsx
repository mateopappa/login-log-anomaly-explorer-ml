import { useEffect, useState } from "react";
import { api, type CaseSummary, type LiveScore } from "../api/client";

function countQueue(rows: CaseSummary[]) {
  const investigated = rows.filter((row) => row.verdict).length;
  return { active: rows.length, investigated, awaiting: rows.length - investigated };
}

export function LiveRunPanel() {
  const [rows, setRows] = useState<CaseSummary[]>([]);
  const [score, setScore] = useState<LiveScore | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      void api
        .cases({ scope: "live" })
        .then((next) => {
          if (!cancelled) setRows(next);
        })
        .catch(() => {
          if (!cancelled) setRows([]);
        });
    };
    load();
    const id = window.setInterval(load, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  async function scoreRun() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.scoreLive();
      setScore(result.metrics);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const counts = countQueue(rows);
  const detectors = score ? (["rules", "ml"] as const) : [];

  return (
    <section className="panel stack">
      <div className="section-head">
        <div>
          <p className="eyebrow">This run</p>
          <h2 style={{ margin: 0, fontSize: "1rem" }}>Queue</h2>
        </div>
        <button className="btn primary" type="button" disabled={busy} onClick={() => void scoreRun()}>
          {busy ? "Scoring…" : "Score this run"}
        </button>
      </div>
      <div className="grid metrics">
        <div className="metric">
          <label>Active</label>
          <strong>{counts.active}</strong>
        </div>
        <div className="metric">
          <label>Investigated</label>
          <strong>{counts.investigated}</strong>
        </div>
        <div className="metric">
          <label>To investigate</label>
          <strong>{counts.awaiting}</strong>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {score && (
        <div className="stack">
          <p className="muted" style={{ margin: 0 }}>
            {score.scenario} · seed {score.seed} · {score.total_events} events
            {score.partial ? " · partial" : ""}
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Detector</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1</th>
                  <th className="num">TP</th>
                  <th className="num">FP</th>
                  <th className="num">FN</th>
                  <th className="num">TN</th>
                </tr>
              </thead>
              <tbody>
                {detectors.map((key) => {
                  const row = score[key];
                  const cm = row.confusion;
                  return (
                    <tr key={key}>
                      <td>{key}</td>
                      <td className="num">{row.enabled ? row.precision : "—"}</td>
                      <td className="num">{row.enabled ? row.recall : "—"}</td>
                      <td className="num">{row.enabled ? row.f1 : "—"}</td>
                      <td className="num">{cm?.tp ?? "—"}</td>
                      <td className="num">{cm?.fp ?? "—"}</td>
                      <td className="num">{cm?.fn ?? "—"}</td>
                      <td className="num">{cm?.tn ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ margin: 0 }}>
            Investigations: correct {score.case_quality.correct} · incorrect {score.case_quality.incorrect} ·
            inconclusive {score.case_quality.inconclusive} · awaiting {score.case_quality.awaiting}
            {score.case_quality.unscored ? ` · unscored ${score.case_quality.unscored}` : ""}
          </p>
          <p className="muted" style={{ margin: 0 }}>
            {score.note}
          </p>
        </div>
      )}
    </section>
  );
}
