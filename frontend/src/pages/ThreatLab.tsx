import { useEffect, useState } from "react";
import { api, type ThreatScenario } from "../api/client";

export function ThreatLab() {
  const [scenarios, setScenarios] = useState<ThreatScenario[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    void api
      .threatScenarios()
      .then((rows) => {
        setScenarios(rows);
        if (rows[0]) setSelected(rows[0].scenario_id);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  async function run(kind: "scenario" | "proposal") {
    setBusy(true);
    setError(null);
    try {
      const payload =
        kind === "proposal"
          ? await api.threatRun({ proposal: true })
          : await api.threatRun({ scenario_id: selected });
      setResult(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <header className="page-header hero-header">
        <div>
          <p className="eyebrow">Threat</p>
          <h1>Threat Lab</h1>
        </div>
        <span className="pulse-badge off">Offline</span>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="panel stack">
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <button className="btn primary" disabled={busy || !selected} onClick={() => void run("scenario")}>
            {busy ? "Running…" : "Run scenario"}
          </button>
          <button className="btn" disabled={busy} onClick={() => void run("proposal")}>
            Run mock proposal
          </button>
        </div>
        {selected && (
          <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
            {scenarios.find((row) => row.scenario_id === selected)?.description}
          </p>
        )}
      </section>

      <section className="panel">
        <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Catalog</h2>
        {scenarios.length === 0 ? (
          <p className="muted">Loading scenarios…</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Strategy</th>
                  <th>Seeds</th>
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {scenarios.map((row) => (
                  <tr key={row.scenario_id} className={selected === row.scenario_id ? "selected" : undefined}>
                    <td className="mono">
                      <button
                        type="button"
                        className="row-select"
                        aria-pressed={selected === row.scenario_id}
                        onClick={() => setSelected(row.scenario_id)}
                      >
                        {row.scenario_id}
                      </button>
                    </td>
                    <td>{row.strategy}</td>
                    <td className="mono">{row.seeds.join(", ")}</td>
                    <td>{row.tags.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {result && (
        <section className="panel">
          <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Latest run · {String(result.evaluation_id)}</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Method</th>
                  <th>P</th>
                  <th>R</th>
                  <th>F1</th>
                </tr>
              </thead>
              <tbody>
                {((result.result as { scenarios?: Array<Record<string, unknown>> })?.scenarios ?? []).flatMap(
                  (scenario) => {
                    const methods = (scenario.methods as Array<Record<string, unknown>>) ?? [];
                    return methods.map((method) => (
                      <tr key={`${String(scenario.scenario_id)}-${String(method.method)}`}>
                        <td className="mono">{String(scenario.scenario_id)}</td>
                        <td>{String(method.method)}</td>
                        <td>{String(method.precision ?? "—")}</td>
                        <td>{String(method.recall ?? "—")}</td>
                        <td>{String(method.f1 ?? "—")}</td>
                      </tr>
                    ));
                  },
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
