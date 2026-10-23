import { useMemo } from "react";

export type FlowEvent = {
  event_id: string;
  timestamp_utc: string;
  account_id: string;
  source_ip: string;
  outcome: string;
  country_code: string;
};

type AlertRow = {
  alert_id?: string;
  rule?: string;
  method?: string;
  event_ids?: string[];
  events?: number;
};

const COUNTRY_LABEL: Record<string, string> = {
  AR: "Argentina",
  BR: "Brazil",
  DE: "Germany",
  JP: "Japan",
  US: "United States",
};

type Props = {
  events: Array<Record<string, unknown>>;
  alerts: Array<Record<string, unknown>>;
};

function asFlowEvent(raw: Record<string, unknown>): FlowEvent | null {
  if (!raw.event_id || !raw.account_id || !raw.source_ip || !raw.country_code) return null;
  return {
    event_id: String(raw.event_id),
    timestamp_utc: String(raw.timestamp_utc ?? ""),
    account_id: String(raw.account_id),
    source_ip: String(raw.source_ip),
    outcome: String(raw.outcome ?? ""),
    country_code: String(raw.country_code),
  };
}

export function SessionFlow({ events, alerts }: Props) {
  const { rows, origins, flaggedCount } = useMemo(() => {
    const ruleByEvent = new Map<string, string[]>();
    for (const alert of alerts as AlertRow[]) {
      const rule = String(alert.rule ?? alert.method ?? "alert");
      for (const eventId of alert.event_ids ?? []) {
        const list = ruleByEvent.get(eventId) ?? [];
        if (!list.includes(rule)) list.push(rule);
        ruleByEvent.set(eventId, list);
      }
    }

    const parsed = events
      .map(asFlowEvent)
      .filter((item): item is FlowEvent => item != null)
      .slice(0, 28);

    const originCounts = new Map<string, { country: string; total: number; flagged: number }>();
    for (const event of parsed) {
      const key = event.country_code;
      const bucket = originCounts.get(key) ?? { country: key, total: 0, flagged: 0 };
      bucket.total += 1;
      if (ruleByEvent.has(event.event_id)) bucket.flagged += 1;
      originCounts.set(key, bucket);
    }

    return {
      rows: parsed.map((event) => ({
        event,
        rules: ruleByEvent.get(event.event_id) ?? [],
        flagged: ruleByEvent.has(event.event_id),
      })),
      origins: [...originCounts.values()].sort((a, b) => b.total - a.total),
      flaggedCount: [...ruleByEvent.keys()].filter((id) => parsed.some((e) => e.event_id === id)).length,
    };
  }, [events, alerts]);

  if (rows.length === 0) {
    return (
      <div className="empty empty-cta">
        <p>Start a session to watch login attempts flow from origin → account.</p>
      </div>
    );
  }

  return (
    <section className="panel stack session-flow">
      <div className="section-head">
        <div>
          <p className="eyebrow">Session flow</p>
          <h2 style={{ margin: 0, fontSize: "1.05rem" }}>Where each attempt comes from</h2>
        </div>
        <span className="muted">
          {flaggedCount} flagged · {rows.length} recent
        </span>
      </div>

      <div className="origin-strip">
        {origins.map((origin) => (
          <div key={origin.country} className={`origin-pill ${origin.flagged ? "hot" : ""}`}>
            <strong>{origin.country}</strong>
            <span>{COUNTRY_LABEL[origin.country] ?? origin.country}</span>
            <span className="mono">
              {origin.total}
              {origin.flagged > 0 ? ` · ${origin.flagged}⚠` : ""}
            </span>
          </div>
        ))}
      </div>

      <ol className="flow-list">
        {rows.map(({ event, rules, flagged }, index) => (
          <li
            key={event.event_id}
            className={`flow-row ${flagged ? "flagged" : "benign"} ${event.outcome}`}
            style={{ animationDelay: `${Math.min(index, 12) * 35}ms` }}
          >
            <div className="flow-node origin">
              <span className="flow-country">{event.country_code}</span>
              <span className="mono flow-ip">{event.source_ip}</span>
            </div>
            <span className="flow-arrow" aria-hidden>
              →
            </span>
            <div className="flow-node account">
              <span className="mono">{event.account_id}</span>
              <span className="muted flow-time">{event.timestamp_utc.slice(11, 19)}</span>
            </div>
            <span className="flow-arrow" aria-hidden>
              →
            </span>
            <div className="flow-node result">
              <span className={`badge ${event.outcome === "failure" ? "high" : "low"}`}>{event.outcome}</span>
              {flagged ? (
                <span className="flow-flags">
                  {rules.map((rule) => (
                    <span key={rule} className="chip chip-strong">
                      {rule}
                    </span>
                  ))}
                </span>
              ) : (
                <span className="muted flow-quiet">benign path</span>
              )}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
