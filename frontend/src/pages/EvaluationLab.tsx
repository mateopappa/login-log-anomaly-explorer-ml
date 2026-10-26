import { useEffect, useState } from "react";
import { api } from "../api/client";

type Metrics = {
  provider_mode?: string;
  provider_id?: string;
  rules?: Record<string, number>;
  ml?: Record<string, number>;
  case_investigations?: Record<string, number>;
};

export function EvaluationLab() {
  const [rows, setRows] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"mock" | "haiku" | null>(null);
  const [latest, setLatest] = useState<{ evaluation_id: string; metrics: Metrics } | null>(null);

  async function refresh() {
    setRows(await api.evaluations());
  }

  useEffect(() => {
    void refresh().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  async function run(provider: "mock" | "haiku") {
    setBusy(provider);
    setError(null);
    try {
      const result = await api.benchmark(42, provider);
      setLatest(result as { evaluation_id: string; metrics: Metrics });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  const metrics = latest?.metrics;

  return (
    <div className="stack">
      <header className="page-header">
        <h1>Scores</h1>
      </header>
      <div className="toolbar">
        <button className="btn primary" disabled={busy !== null} onClick={() => void run("mock")}>
          {busy === "mock" ? "Running…" : "Benchmark mock"}
        </button>
        <button className="btn" disabled={busy !== null} onClick={() => void run("haiku")}>
          {busy === "haiku" ? "Running…" : "Benchmark Haiku"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      {metrics && (
        <section className="panel stack">
          <h2 style={{ margin: 0, fontSize: "1rem" }}>
            Latest · {latest?.evaluation_id} · {metrics.provider_mode}/{metrics.provider_id}
          </h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Detector</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1</th>
                  <th>TP</th>
                  <th>FP</th>
                  <th>FN</th>
                </tr>
              </thead>
              <tbody>
                {(["rules", "ml"] as const).map((key) => {
                  const row = metrics[key] ?? {};
                  return (
                    <tr key={key}>
                      <td>{key}</td>
                      <td>{row.precision ?? "—"}</td>
                      <td>{row.recall ?? "—"}</td>
                      <td>{row.f1 ?? "—"}</td>
                      <td>{row.tp ?? "—"}</td>
                      <td>{row.fp ?? "—"}</td>
                      <td>{row.fn ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {metrics.case_investigations && (
            <p className="muted" style={{ margin: 0 }}>
              Case investigations: total {metrics.case_investigations.total ?? 0} · correct{" "}
              {metrics.case_investigations.correct ?? 0} · incorrect {metrics.case_investigations.incorrect ?? 0} ·
              inconclusive {metrics.case_investigations.inconclusive ?? 0}
            </p>
          )}
        </section>
      )}
      <section className="panel">
        <h2 style={{ marginTop: 0, fontSize: "1rem" }}>History</h2>
        {rows.length === 0 ? (
          <p className="muted">No evaluation runs yet.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Seed</th>
                  <th>Provider</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={String(row.evaluation_id)}>
                    <td className="mono">{String(row.evaluation_id)}</td>
                    <td>{String(row.seed)}</td>
                    <td>{String((row.config as { provider?: string } | undefined)?.provider ?? "—")}</td>
                    <td className="mono">{String(row.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
