import { useEffect, useMemo, useState } from "react";

type AlertRow = {
  alert_id?: string;
  rule?: string;
  method?: string;
  severity?: string;
  event_ids?: string[];
  events?: number;
};

const SITES = [
  { code: "US", name: "United States" },
  { code: "JP", name: "Japan" },
  { code: "AR", name: "Argentina" },
  { code: "DE", name: "Germany" },
  { code: "BR", name: "Brazil" },
] as const;

type Props = {
  events: Array<Record<string, unknown>>;
  alerts: Array<Record<string, unknown>>;
  running?: boolean;
};

type SiteStat = {
  code: string;
  name: string;
  count: number;
  failures: number;
  successes: number;
  flagged: number;
  flash: "success" | "failure" | null;
};

export function SessionFlow({ events, alerts, running = false }: Props) {
  const [flashByCode, setFlashByCode] = useState<Record<string, "success" | "failure">>({});

  const { sites, alertRows, flaggedCount, recentCount } = useMemo(() => {
    const flaggedIds = new Set<string>();
    for (const alert of alerts as AlertRow[]) {
      for (const eventId of alert.event_ids ?? []) flaggedIds.add(eventId);
    }

    const recent = events.slice(0, 28);
    const byCode: Record<string, { count: number; failures: number; successes: number; flagged: number }> = {};
    for (const site of SITES) {
      byCode[site.code] = { count: 0, failures: 0, successes: 0, flagged: 0 };
    }
    for (const raw of recent) {
      const code = String(raw.country_code ?? "");
      if (!byCode[code]) continue;
      byCode[code].count += 1;
      if (String(raw.outcome ?? "") === "failure") byCode[code].failures += 1;
      else byCode[code].successes += 1;
      if (flaggedIds.has(String(raw.event_id ?? ""))) byCode[code].flagged += 1;
    }

    const siteRows: SiteStat[] = SITES.map((site) => ({
      code: site.code,
      name: site.name,
      count: byCode[site.code].count,
      failures: byCode[site.code].failures,
      successes: byCode[site.code].successes,
      flagged: byCode[site.code].flagged,
      flash: null,
    }));

    return {
      sites: siteRows,
      alertRows: (alerts as AlertRow[]).slice(0, 20),
      flaggedCount: flaggedIds.size,
      recentCount: recent.length,
    };
  }, [events, alerts]);

  useEffect(() => {
    const newest = events[0];
    if (!newest) return;
    const code = String(newest.country_code ?? "");
    if (!SITES.some((site) => site.code === code)) return;
    const outcome = String(newest.outcome ?? "") === "failure" ? "failure" : "success";
    setFlashByCode((prev) => ({ ...prev, [code]: outcome }));
    const id = window.setTimeout(() => {
      setFlashByCode((prev) => {
        const next = { ...prev };
        delete next[code];
        return next;
      });
    }, 700);
    return () => window.clearTimeout(id);
  }, [events]);

  return (
    <section className="panel stack session-flow">
      <div className="section-head">
        <div>
          <p className="eyebrow">Session flow</p>
          <h2 style={{ margin: 0, fontSize: "1.05rem" }}>Where each attempt comes from</h2>
        </div>
        <span className="muted">
          {flaggedCount} flagged · {recentCount} recent
        </span>
      </div>

      <div className="origin-strip" aria-label="Login origins">
        {sites.map((site) => {
          const flash = flashByCode[site.code] ?? null;
          const hot = site.count > 0;
          const tone =
            flash ??
            (site.failures > site.successes ? "failure" : site.successes > 0 ? "success" : null);
          return (
            <div
              key={site.code}
              className={[
                "origin-pill",
                hot ? "hot" : "",
                tone ? `tone-${tone}` : "",
                flash ? "flash" : "",
                running && hot ? "live" : "",
              ]
                .filter(Boolean)
                .join(" ")}
            >
              <strong>{site.code}</strong>
              <span>{site.name}</span>
              <span className="origin-count">
                {site.count}
                {site.flagged > 0 ? ` · ${site.flagged} alert` : ""}
              </span>
            </div>
          );
        })}
      </div>

      <div className="section-head" style={{ marginTop: "0.35rem" }}>
        <h2 style={{ margin: 0, fontSize: "1rem" }}>Alerts</h2>
        <span className="muted">{alertRows.length}</span>
      </div>
      {alertRows.length === 0 ? (
        <p className="muted" style={{ margin: 0 }}>
          No alerts yet — keep the sim running.
        </p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Events</th>
              </tr>
            </thead>
            <tbody>
              {alertRows.map((alert) => (
                <tr key={String(alert.alert_id)}>
                  <td>{String(alert.method ?? "—")}</td>
                  <td className="mono">{String(alert.rule ?? "—")}</td>
                  <td>
                    <span className={`badge ${String(alert.severity ?? "")}`}>
                      {String(alert.severity ?? "—")}
                    </span>
                  </td>
                  <td>{String(alert.events ?? alert.event_ids?.length ?? "—")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
