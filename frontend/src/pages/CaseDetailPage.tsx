import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type CaseDetail, type InvestigationRun } from "../api/client";
import { ProviderBadge } from "../components/ProviderBadge";

export function CaseDetailPage() {
  const { caseId = "" } = useParams();
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"mock" | "haiku" | null>(null);
  const [latest, setLatest] = useState<InvestigationRun | null>(null);

  async function load() {
    const data = await api.caseDetail(caseId);
    setDetail(data);
    setLatest(data.investigations.at(-1) ?? null);
  }

  useEffect(() => {
    void load().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [caseId]);

  async function investigate(provider: "mock" | "haiku") {
    setBusy(provider);
    setError(null);
    try {
      const run = await api.investigate(caseId, provider, `${caseId}-${provider}-${Date.now()}`);
      setLatest(run);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  if (!detail && !error) return <div className="empty">Loading case…</div>;
  if (!detail) return <div className="error">{error}</div>;

  const run = latest;

  return (
    <div className="stack">
      <header className="page-header">
        <p className="muted">
          <Link to="/cases">Cases</Link> / <span className="mono">{detail.case_id}</span>
        </p>
        <h1>Case dossier</h1>
        <p>
          {detail.kind} · {detail.priority} · {detail.status}
        </p>
      </header>

      {error && <div className="error">{error}</div>}

      <div className="toolbar">
        <button className="btn primary" disabled={busy !== null} onClick={() => void investigate("mock")}>
          {busy === "mock" ? "Running mock…" : "Investigate (mock)"}
        </button>
        <button className="btn" disabled={busy !== null} onClick={() => void investigate("haiku")}>
          {busy === "haiku" ? "Running Haiku…" : "Investigate (Claude Haiku)"}
        </button>
      </div>

      <section className="panel">
        <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Related events</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Account</th>
                <th>IP</th>
                <th>Outcome</th>
                <th>Country</th>
                <th>Event</th>
              </tr>
            </thead>
            <tbody>
              {detail.events.map((event) => (
                <tr key={event.event_id}>
                  <td className="mono">{event.timestamp_utc}</td>
                  <td className="mono">{event.account_id}</td>
                  <td className="mono">{event.source_ip}</td>
                  <td>{event.outcome}</td>
                  <td>{event.country_code}</td>
                  <td className="mono">{event.event_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {run && (
        <>
          <section className="panel stack">
            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
              <h2 style={{ margin: 0, fontSize: "1rem" }}>Investigation</h2>
              <ProviderBadge mode={run.mode} providerId={run.provider_id} model={run.model} />
              <span className={`badge ${run.result?.verdict ?? ""}`}>{run.result?.verdict ?? run.status}</span>
              {run.result?.risk_level && <span className={`badge ${run.result.risk_level}`}>risk {run.result.risk_level}</span>}
            </div>
            <p style={{ margin: 0 }}>{run.result?.justification ?? "No conclusion yet."}</p>
            <p className="muted" style={{ margin: 0 }}>
              Status {run.status}
              {run.latency_ms != null ? ` · ${run.latency_ms} ms` : ""}
              {run.tokens_in != null ? ` · tokens in/out ${run.tokens_in}/${run.tokens_out}` : ""}
              {run.cost_usd_est != null ? ` · ~$${run.cost_usd_est}` : ""}
            </p>
          </section>

          <section className="panel">
            <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Evidence</h2>
            {(run.result?.evidence?.length ?? 0) === 0 ? (
              <p className="muted">No evidence citations.</p>
            ) : (
              <ul>
                {run.result?.evidence.map((item, index) => (
                  <li key={`${item.event_id}-${index}`}>
                    <span className="mono">{item.event_id}</span> · {item.field}: {item.summary}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel">
            <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Tool calls</h2>
            {run.tool_calls.length === 0 ? (
              <p className="muted">No tool calls recorded on this run.</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Tool</th>
                      <th>Status</th>
                      <th>Arguments</th>
                    </tr>
                  </thead>
                  <tbody>
                    {run.tool_calls.map((call) => (
                      <tr key={call.seq}>
                        <td>{call.seq}</td>
                        <td className="mono">{call.tool_name}</td>
                        <td>{call.status}</td>
                        <td className="mono">{JSON.stringify(call.arguments)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="panel">
            <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Limitations / uncertainty</h2>
            <ul>
              {(run.result?.limitations ?? []).map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>

          <section className="panel">
            <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Hypotheses</h2>
            {(run.result?.hypotheses?.length ?? 0) === 0 ? (
              <p className="muted">
                No structured hypotheses on this run. Optional field for providers that contrast alternatives; mock often
                leaves this empty.
              </p>
            ) : (
              <ul>
                {run.result?.hypotheses.map((item, index) => (
                  <li key={`${item.stance}-${index}`}>
                    <span className={`badge ${item.stance === "supports" ? "malicious" : item.stance === "contradicts" ? "benign" : "inconclusive"}`}>
                      {item.stance}
                    </span>{" "}
                    {item.statement}
                    {item.evidence_event_ids?.length ? (
                      <span className="muted"> · events {item.evidence_event_ids.join(", ")}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </section>

          {run.review && (
            <section className="panel">
              <h2 style={{ marginTop: 0, fontSize: "1rem" }}>Deterministic reviewer</h2>
              <p>
                <span className="badge">{run.review.mode}</span>{" "}
                <span className="badge">{run.review.quality}</span>
              </p>
              {(run.review.deficiencies?.length ?? 0) > 0 && (
                <>
                  <h3 style={{ fontSize: "0.9rem" }}>Deficiencies</h3>
                  <ul>
                    {run.review.deficiencies?.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </>
              )}
              {(run.review.strengths?.length ?? 0) > 0 && (
                <>
                  <h3 style={{ fontSize: "0.9rem" }}>Strengths</h3>
                  <ul>
                    {run.review.strengths?.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </>
              )}
            </section>
          )}
        </>
      )}
    </div>
  );
}
