import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type CaseSummary } from "../api/client";
import { ProviderBadge } from "../components/ProviderBadge";

export function CasesPage() {
  const [rows, setRows] = useState<CaseSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .cases()
      .then(setRows)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  return (
    <div>
      <header className="page-header">
        <h1>Cases</h1>
      </header>
      {error && <div className="error">{error}</div>}
      {rows.length === 0 && !error ? (
        <div className="empty">
          No cases. <Link to="/">Load a dataset</Link> on Console.
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Kind</th>
                <th>Priority</th>
                <th>Events</th>
                <th>Verdict</th>
                <th>Provider</th>
                <th>Review</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.case_id}>
                  <td className="mono">
                    <Link to={`/cases/${row.case_id}`}>{row.case_id.slice(0, 20)}…</Link>
                  </td>
                  <td>{row.kind}</td>
                  <td>{row.priority}</td>
                  <td>{row.events}</td>
                  <td>
                    <span className={`badge ${row.verdict ?? ""}`}>{row.verdict ?? "—"}</span>
                  </td>
                  <td>
                    <ProviderBadge mode={row.mode} providerId={row.provider_id} />
                  </td>
                  <td>{row.review ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
