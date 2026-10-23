import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type CaseDetail, type CaseEvaluation, type InvestigationRun } from "../api/client";
import { ProviderBadge } from "../components/ProviderBadge";
import { buildCaseResume, summarizeEvents, type CaseSignal } from "../lib/caseResume";

export function CaseDetailPage() {
  const { caseId = "" } = useParams();
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"mock" | "haiku" | "evaluate" | null>(null);
  const [latest, setLatest] = useState<InvestigationRun | null>(null);
  const [evaluation, setEvaluation] = useState<CaseEvaluation | null>(null);

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
      setEvaluation(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function evaluate() {
    setBusy("evaluate");
    setError(null);
    try {
      const scored = await api.evaluateCase(caseId, latest?.run_id);
      setEvaluation(scored);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  const resume = useMemo(() => {
    if (!detail) return null;
    return buildCaseResume(detail.kind, detail.signals as CaseSignal[]);
  }, [detail]);

  const eventSummary = useMemo(() => {
    if (!detail) return null;
    return summarizeEvents(detail.events);
  }, [detail]);

  if (!detail && !error) return <div className="empty">Loading case…</div>;
  if (!detail || !resume || !eventSummary) return <div className="error">{error}</div>;

  const run = latest;

  return (
    <div className="stack">
      <header className="page-header hero-header">
        <div>
          <p className="muted">
            <Link to="/cases">Cases</Link> / <span className="mono">{detail.case_id}</span>
          </p>
          <h1>Case dossier</h1>
          <p>
            Suspected <strong>{resume.attackGuess}</strong>
            {" · "}
            {detail.priority} priority
          </p>
        </div>
        <div className="hero-actions">
          <button className="btn primary btn-xl" disabled={busy !== null} onClick={() => void investigate("mock")}>
            {busy === "mock" ? "Running…" : "Investigate (mock)"}
          </button>
          <button className="btn btn-xl" disabled={busy !== null} onClick={() => void investigate("haiku")}>
            {busy === "haiku" ? "Running…" : "Investigate (Haiku)"}
          </button>
          <button className="btn btn-xl" disabled={busy !== null || !run} onClick={() => void evaluate()}>
            {busy === "evaluate" ? "Scoring…" : "Evaluate vs GT"}
          </button>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="panel case-resume">
        <p className="eyebrow">Quick resume</p>
        <div className="grid metrics">
          <div className="metric">
            <label>Detector</label>
            <strong>{resume.source}</strong>
            <span className="muted metric-sub">{resume.sourceDetail}</span>
          </div>
          <div className="metric">
            <label>Suspected attack</label>
            <strong>{resume.attackGuess}</strong>
            <span className="muted metric-sub">
              {resume.severities.length ? resume.severities.join(" · ") : detail.kind}
            </span>
          </div>
          <div className="metric">
            <label>Priority</label>
            <strong className={detail.priority}>{detail.priority}</strong>
            <span className="muted metric-sub">{detail.status}</span>
          </div>
          <div className="metric">
            <label>Scope</label>
            <strong>
              {detail.events.length} evt · {eventSummary.accounts} acct
            </strong>
            <span className="muted metric-sub">
              {eventSummary.countries.join(", ")} · {eventSummary.failures} fail / {eventSummary.successes} ok
            </span>
          </div>
        </div>
        {resume.attackRules.length > 0 && (
          <div className="chip-row" style={{ marginTop: "0.85rem" }}>
            {resume.attackRules.map((rule) => (
              <span key={rule} className="chip chip-strong">
                {rule}
              </span>
            ))}
          </div>
        )}
      </section>

      <details className="panel collapsible">
        <summary>
          <strong>Related events</strong>
          <span className="muted">
            {detail.events.length} collapsed · {eventSummary.countries.join(" → ") || "—"}
          </span>
        </summary>
        <div className="table-wrap" style={{ marginTop: "0.75rem" }}>
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
      </details>

      {evaluation && (
        <section className="panel stack case-eval">
          <div className="section-head">
            <div>
              <p className="eyebrow">Offline evaluation</p>
              <h2 style={{ margin: 0, fontSize: "1.05rem" }}>This case vs ground truth</h2>
            </div>
            <span className={`badge ${evaluation.metrics.verdict_match === "correct" ? "benign" : evaluation.metrics.verdict_match === "incorrect" ? "malicious" : "inconclusive"}`}>
              {evaluation.metrics.verdict_match}
            </span>
          </div>
          <div className="grid metrics">
            <div className="metric">
              <label>Expected</label>
              <strong>{evaluation.metrics.expected_verdict}</strong>
              <span className="muted metric-sub">
                {evaluation.metrics.expected_malicious ? "has malicious events" : "all benign in case"}
              </span>
            </div>
            <div className="metric">
              <label>Investigator said</label>
              <strong>{evaluation.metrics.actual_verdict}</strong>
              <span className="muted metric-sub">
                {evaluation.mode}/{evaluation.provider_id}
              </span>
            </div>
            <div className="metric">
              <label>GT overlap</label>
              <strong>
                {evaluation.metrics.malicious_event_count}/{evaluation.metrics.event_count}
              </strong>
              <span className="muted metric-sub">malicious events in case</span>
            </div>
            <div className="metric">
              <label>Policy</label>
              <strong>
                {evaluation.metrics.policy.forbidden_access_attempts + evaluation.metrics.policy.tool_limit_violations === 0
                  ? "clean"
                  : "issues"}
              </strong>
              <span className="muted metric-sub">
                {evaluation.metrics.policy.steps} steps · {evaluation.metrics.policy.unsupported_evidence} bad cites
              </span>
            </div>
          </div>
          {(evaluation.metrics.policy.findings.length > 0 || evaluation.metrics.malicious_event_ids.length > 0) && (
            <div className="chip-row">
              {evaluation.metrics.malicious_event_ids.slice(0, 6).map((id) => (
                <span key={id} className="chip chip-strong mono">
                  GT {id}
                </span>
              ))}
              {evaluation.metrics.policy.findings.map((item) => (
                <span key={item} className="chip">
                  {item}
                </span>
              ))}
            </div>
          )}
          <p className="muted" style={{ margin: 0, fontSize: "0.82rem" }}>
            {evaluation.metrics.note} · {evaluation.evaluation_id}
          </p>
        </section>
      )}

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

          <details className="panel collapsible">
            <summary>
              <strong>Tool calls</strong>
              <span className="muted">{run.tool_calls.length}</span>
            </summary>
            {run.tool_calls.length === 0 ? (
              <p className="muted">No tool calls recorded on this run.</p>
            ) : (
              <div className="table-wrap" style={{ marginTop: "0.75rem" }}>
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
          </details>

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
              <p className="muted">No structured hypotheses on this run.</p>
            ) : (
              <ul>
                {run.result?.hypotheses.map((item, index) => (
                  <li key={`${item.stance}-${index}`}>
                    <span
                      className={`badge ${
                        item.stance === "supports" ? "malicious" : item.stance === "contradicts" ? "benign" : "inconclusive"
                      }`}
                    >
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

      {!run && (
        <div className="empty empty-cta">
          <p>No investigation yet — run mock or Haiku.</p>
        </div>
      )}
    </div>
  );
}
