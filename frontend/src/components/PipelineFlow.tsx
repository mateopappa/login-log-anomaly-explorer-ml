type ObsLinks = {
  redpanda: string;
  grafana: string;
  prometheus: string;
};

type Props = {
  links: ObsLinks;
  workerLive: boolean;
};

const NODES = [
  {
    id: "sites",
    title: "Sites",
    detail: "5 tenants publish AuthEvents",
  },
  {
    id: "redpanda",
    title: "Redpanda",
    detail: "Topics & message payloads",
    hrefKey: "redpanda" as const,
    hrefLabel: "Open console",
  },
  {
    id: "worker",
    title: "Worker",
    detail: "Rules only · metrics out · no case DB",
  },
  {
    id: "prometheus",
    title: "Prometheus",
    detail: "Scrapes worker /metrics",
    hrefKey: "prometheus" as const,
    hrefLabel: "Open Prom",
  },
  {
    id: "grafana",
    title: "Grafana",
    detail: "Login Anomaly dashboard",
    hrefKey: "grafana" as const,
    hrefLabel: "Open Grafana",
  },
];

export function PipelineFlow({ links, workerLive }: Props) {
  return (
    <section className="flow-panel" aria-label="Event pipeline flow">
      <div className="flow-head">
        <div>
          <p className="eyebrow">Flow</p>
          <h2 className="flow-title">Sites → Redpanda → Worker → Prom → Grafana</h2>
        </div>
        <span className={`pulse-badge ${workerLive ? "on" : "off"}`}>
          <span className={`pulse-dot ${workerLive ? "on" : ""}`} />
          {workerLive ? "Worker live" : "Worker offline"}
        </span>
      </div>

      <ol className="flow-track">
        {NODES.map((node, index) => {
          const href = node.hrefKey ? links[node.hrefKey] : undefined;
          return (
            <li key={node.id} className="flow-step">
              {index > 0 && (
                <span className="flow-arrow" aria-hidden>
                  →
                </span>
              )}
              <div className={`flow-node ${node.hrefKey ? "linked" : ""}`}>
                <strong>{node.title}</strong>
                <p>{node.detail}</p>
                {href && (
                  <a className="flow-link" href={href} target="_blank" rel="noreferrer">
                    {node.hrefLabel}
                  </a>
                )}
              </div>
            </li>
          );
        })}
      </ol>

      <p className="flow-aside muted">
        Cases persist via Console seed / Live → Postgres. This path: rules + metrics only.
      </p>
    </section>
  );
}
