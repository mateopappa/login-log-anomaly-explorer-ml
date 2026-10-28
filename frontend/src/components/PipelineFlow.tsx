type ObsLinks = {
  redpanda: string;
  grafana: string;
  prometheus: string;
};

type Props = {
  links: ObsLinks;
  workerLive: boolean;
  /** When true, animate packets along the workflow cables. */
  traffic?: boolean;
};

const SITE_CODES = ["US", "JP", "AR", "DE", "BR"] as const;

type JobStatus = "success" | "in_progress" | "queued" | "failure";

type Job = {
  id: string;
  name: string;
  runsOn: string;
  steps: string[];
  hrefKey?: keyof ObsLinks;
};

const JOBS: Job[] = [
  {
    id: "sites",
    name: "sites",
    runsOn: "producers",
    steps: ["Publish AuthEvents", "US · JP · AR · DE · BR"],
  },
  {
    id: "redpanda",
    name: "redpanda",
    runsOn: "broker",
    steps: ["Ingest envelopes", "Retain topics"],
    hrefKey: "redpanda",
  },
  {
    id: "worker",
    name: "worker",
    runsOn: "rules",
    steps: ["Consume batches", "Run rule detect", "Export /metrics"],
  },
  {
    id: "prometheus",
    name: "prometheus",
    runsOn: "scrape",
    steps: ["Scrape worker", "Store series"],
    hrefKey: "prometheus",
  },
  {
    id: "grafana",
    name: "grafana",
    runsOn: "dashboard",
    steps: ["Login Anomaly board"],
    hrefKey: "grafana",
  },
];

function jobStatus(id: string, workerLive: boolean): JobStatus {
  if (!workerLive) {
    if (id === "sites") return "success";
    if (id === "worker") return "failure";
    return "queued";
  }
  if (id === "worker") return "in_progress";
  return "success";
}

function StatusIcon({ status }: { status: JobStatus }) {
  if (status === "success") {
    return (
      <span className="wf-icon success" aria-label="Success" title="Success">
        <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden>
          <path
            fill="currentColor"
            d="M8 16A8 8 0 1 1 8 0a8 8 0 0 1 0 16Zm3.78-9.72a.75.75 0 0 0-1.06-1.06L7.25 9.19 5.28 7.22a.75.75 0 0 0-1.06 1.06l2.5 2.5a.75.75 0 0 0 1.06 0l4-4Z"
          />
        </svg>
      </span>
    );
  }
  if (status === "in_progress") {
    return (
      <span className="wf-icon progress" aria-label="In progress" title="In progress">
        <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden>
          <path
            fill="currentColor"
            d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Zm7-3.25v2.992l2.028.812a.75.75 0 0 1-.557 1.392l-2.5-1A.751.751 0 0 1 7 8.25v-3.5a.75.75 0 0 1 1.5 0Z"
          />
        </svg>
      </span>
    );
  }
  if (status === "failure") {
    return (
      <span className="wf-icon failure" aria-label="Failure" title="Failure">
        <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden>
          <path
            fill="currentColor"
            d="M2.343 13.657A8 8 0 1 1 13.658 2.343 8 8 0 0 1 2.343 13.657ZM6.03 4.97a.751.751 0 0 0-1.042.018.75.75 0 0 0-.018 1.042L6.94 8l-1.97 1.97a.749.749 0 0 0 .326 1.275.75.75 0 0 0 .734-.215L8 9.06l1.97 1.97a.749.749 0 0 0 1.275-.326.75.75 0 0 0-.215-.734L9.06 8l1.97-1.97a.749.749 0 0 0-.326-1.275.75.75 0 0 0-.734.215L8 6.94Z"
          />
        </svg>
      </span>
    );
  }
  return (
    <span className="wf-icon queued" aria-label="Queued" title="Queued">
      <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden>
        <path
          fill="currentColor"
          d="M8 4a4 4 0 1 1 0 8 4 4 0 0 1 0-8Zm0-2a6 6 0 1 0 0 12A6 6 0 0 0 8 2Z"
        />
      </svg>
    </span>
  );
}

export function PipelineFlow({ links, workerLive, traffic }: Props) {
  const runStatus: JobStatus = workerLive ? "in_progress" : "queued";
  const runLabel = workerLive ? "In progress" : "Queued";
  const packetsOn = Boolean(traffic ?? workerLive);

  return (
    <section className="wf-graph" aria-label="Pipeline workflow graph">
      <header className="wf-run-head">
        <div className="wf-run-title">
          <StatusIcon status={runStatus} />
          <div>
            <p className="wf-file mono">pipeline.yml</p>
            <h2 className="wf-run-name">multi-site ingest</h2>
          </div>
        </div>
        <span className={`wf-run-badge ${runStatus}`}>{runLabel}</span>
      </header>

      <div className={`wf-sites-row ${packetsOn ? "live" : ""}`} aria-label="Five origin sites">
        {SITE_CODES.map((code, index) => (
          <span key={code} className="wf-site-chip" style={{ animationDelay: `${index * 0.12}s` }}>
            {code}
          </span>
        ))}
        <span className="wf-sites-join" aria-hidden />
      </div>

      <div className="wf-canvas" role="list">
        {JOBS.map((job, index) => {
          const status = jobStatus(job.id, workerLive);
          const href = job.hrefKey ? links[job.hrefKey] : undefined;
          return (
            <div key={job.id} className="wf-job-wrap" role="listitem">
              {index > 0 && (
                <div className={`wf-edge ${packetsOn ? "live" : ""}`} aria-hidden>
                  <span className="wf-edge-line" />
                  {packetsOn && (
                    <span className="wf-packet" style={{ animationDelay: `${(index - 1) * 0.4}s` }} />
                  )}
                </div>
              )}
              <article className={`wf-job ${status}`}>
                <header className="wf-job-head">
                  <StatusIcon status={status} />
                  <div className="wf-job-names">
                    <strong className="mono">{job.name}</strong>
                    <span className="muted mono">runs-on: {job.runsOn}</span>
                  </div>
                </header>
                <ul className="wf-steps">
                  {job.steps.map((step) => (
                    <li key={step}>
                      <span className="wf-step-dot" aria-hidden />
                      {step}
                    </li>
                  ))}
                </ul>
                {href && (
                  <a className="wf-job-link" href={href} target="_blank" rel="noreferrer">
                    Open
                  </a>
                )}
              </article>
            </div>
          );
        })}
      </div>

      <p className="wf-note muted">
        Benign / non-flagged traffic stays on these broker topics. Flagged work becomes Cases via
        Console seed or Live → Postgres. This graph: rules + metrics only.
      </p>
    </section>
  );
}
