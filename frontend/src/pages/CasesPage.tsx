import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type CaseSummary } from "../api/client";
import { LiveRunPanel } from "../components/LiveRunPanel";
import { ProviderBadge } from "../components/ProviderBadge";

type Scope = "sites" | "latest" | "live" | "all";

const PRIORITY_RANK: Record<string, number> = {
  rule_high: 0,
  rule_medium: 1,
  ml_untriaged: 2,
};

function byTriage(a: CaseSummary, b: CaseSummary): number {
  const rank = (PRIORITY_RANK[a.priority] ?? 9) - (PRIORITY_RANK[b.priority] ?? 9);
  if (rank !== 0) return rank;
  return b.events - a.events;
}

const SCOPES: { id: Scope; label: string }[] = [
  { id: "sites", label: "Sites" },
  { id: "latest", label: "Batch" },
  { id: "live", label: "Live" },
  { id: "all", label: "All" },
];

function isScope(value: string | null): value is Scope {
  return value === "sites" || value === "latest" || value === "live" || value === "all";
}

export function CasesPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("scope");
  const explicit = isScope(requested) ? requested : null;
  const [scope, setScope] = useState<Scope | null>(explicit);
  const [rows, setRows] = useState<CaseSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (explicit) {
      setScope(explicit);
      return;
    }
    let cancelled = false;
    void api
      .liveStatus()
      .then((live) => {
        if (!cancelled) setScope(live.active ? "live" : "sites");
      })
      .catch(() => {
        if (!cancelled) setScope("sites");
      });
    return () => {
      cancelled = true;
    };
  }, [explicit]);

  useEffect(() => {
    if (!scope) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    const load = (quiet: boolean) => {
      void api
        .cases({ scope })
        .then((next) => {
          if (!cancelled) setRows(next);
        })
        .catch((err) => {
          if (!cancelled && !quiet) setError(err instanceof Error ? err.message : String(err));
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    };
    load(false);
    if (scope !== "live") return () => {
      cancelled = true;
    };
    const id = window.setInterval(() => load(true), 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [scope]);

  const queued = [...rows].sort(byTriage);
  const awaiting = queued.filter((row) => !row.verdict).length;

  return (
    <div>
      <header className="page-header hero-header">
        <div>
          <h1>Cases</h1>
          <p className="muted">
            High-severity rule alerts stay with the detector. This queue is what still needs an investigator. Reset clears this Live run only.
            {scope === "live" && queued.length > 0 ? ` ${awaiting} awaiting.` : ""}
          </p>
        </div>
        <div className="hero-actions scope-toggle" role="group" aria-label="Dataset scope">
          {SCOPES.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`btn ${scope === item.id ? "primary" : ""}`}
              aria-pressed={scope === item.id}
              onClick={() => setSearchParams({ scope: item.id })}
            >
              {item.label}
            </button>
          ))}
        </div>
      </header>
      {scope === "live" && <LiveRunPanel />}
      {error && <div className="error">{error}</div>}
      {loading ? (
        <div className="empty">Loading…</div>
      ) : rows.length === 0 && !error ? (
        <div className="empty">
          {scope === "live"
            ? "No open cases in this sim."
            : scope === "sites"
              ? "No cases from the latest publish of each site yet."
              : "No cases in this view."}{" "}
          <Link to="/">Batch and Live</Link> stay on the other toggles.
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                {scope === "sites" && <th>Site</th>}
                {scope === "all" && <th>Dataset</th>}
                <th>Kind</th>
                <th>Priority</th>
                <th>Status</th>
                <th className="num">Events</th>
                <th>Verdict</th>
                <th>Provider</th>
                <th>Review</th>
              </tr>
            </thead>
            <tbody>
              {queued.map((row) => (
                <tr key={row.case_id}>
                  <td className="mono">
                    <Link to={`/cases/${row.case_id}`} aria-label={row.case_id}>
                      {row.case_id.slice(0, 20)}…
                    </Link>
                  </td>
                  {scope === "sites" && <td>{row.site || "—"}</td>}
                  {scope === "all" && <td className="mono">{row.dataset_id.slice(0, 14)}…</td>}
                  <td>{row.kind}</td>
                  <td>
                    <span className={`badge ${row.priority === "rule_high" ? "high" : row.priority === "rule_medium" ? "medium" : "inconclusive"}`}>
                      {row.priority}
                    </span>
                  </td>
                  <td>{row.status}</td>
                  <td className="num">{row.events}</td>
                  <td>
                    <span className={`badge ${row.verdict ?? "inconclusive"}`}>{row.verdict ?? "awaiting"}</span>
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
