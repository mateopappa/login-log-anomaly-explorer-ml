const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!response.ok) {
    const detail = await response.text();
    let message = detail;
    try {
      const parsed = JSON.parse(detail) as { detail?: unknown };
      if (typeof parsed.detail === "string") message = parsed.detail;
    } catch {
      message = detail;
    }
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export type CaseSummary = {
  case_id: string;
  dataset_id: string;
  site?: string | null;
  kind: string;
  priority: string;
  status: string;
  events: number;
  signals: number;
  verdict: string | null;
  mode: string | null;
  provider_id: string | null;
  review: string | null;
  updated_at: string;
};

export type InvestigationRun = {
  run_id: string;
  case_id: string;
  status: string;
  mode: string;
  provider_id: string;
  model: string | null;
  steps: number;
  errors: string[];
  latency_ms: number | null;
  tokens_in: number | null;
  tokens_out: number | null;
  cost_usd_est: number | null;
  tool_calls: Array<{
    seq: number;
    tool_name: string;
    arguments: Record<string, unknown>;
    status: string;
  }>;
  result: {
    verdict: string;
    confidence: number;
    risk_level: string | null;
    justification: string;
    limitations: string[];
    evidence: Array<{ event_id: string; field: string; summary: string }>;
    hypotheses: Array<{
      statement: string;
      stance: string;
      evidence_event_ids: string[];
    }>;
  } | null;
  review: {
    mode: string;
    quality: string;
    strengths?: string[];
    deficiencies?: string[];
    uncertainty?: string[];
    policy_findings?: string[];
  } | null;
};

export type CaseDetail = {
  case_id: string;
  dataset_id: string;
  kind: string;
  priority: string;
  status: string;
  event_ids: string[];
  signals: Array<Record<string, unknown>>;
  associations: unknown[];
  events: Array<{
    event_id: string;
    timestamp_utc: string;
    account_id: string;
    source_ip: string;
    outcome: string;
    country_code: string;
  }>;
  investigations: InvestigationRun[];
};

export type CaseEvaluation = {
  evaluation_id: string;
  case_id: string;
  run_id: string;
  provider_id: string;
  mode: string;
  metrics: {
    expected_malicious: boolean;
    expected_verdict: string;
    actual_verdict: string;
    verdict_match: string;
    verdict_correct: boolean | null;
    malicious_event_ids: string[];
    malicious_event_count: number;
    event_count: number;
    policy: {
      unsupported_evidence: number;
      irrelevant_evidence: number;
      forbidden_access_attempts: number;
      tool_limit_violations: number;
      failed_tool_calls: number;
      steps: number;
      findings: string[];
    };
    note: string;
  };
};

export type SocSummary = {
  cases_open: number;
  cases_total: number;
  recent_cases: Array<Record<string, unknown>>;
  live: Record<string, unknown> | null;
  investigator: {
    default: string;
    mock_available: boolean;
    haiku_configured: boolean;
    haiku_model: string | null;
  };
  services: Record<string, string>;
  active_dataset_id?: string | null;
  active_seed?: number | null;
  events_total?: number;
  cases_by_kind?: Record<string, number>;
  scope?: "sites" | "latest" | "live" | "all";
  live_dataset_id?: string | null;
};

export type LiveSummary = {
  released: number;
  generated: number;
  pending?: number;
  rule_alerts: number;
  cases_open: number;
  cases_total?: number;
  investigations_completed: number;
  simulated_time: string | null;
  elapsed_seconds?: number;
  mode?: string;
  seed?: number;
  scenario?: string | null;
  message?: string;
  state?: string;
};

export type LiveDetectorScore = {
  enabled: boolean;
  precision: number;
  recall: number;
  f1: number;
  confusion: { tp: number; fp: number; fn: number; tn: number } | null;
};

export type LiveScore = {
  simulation_id?: string;
  scenario: string;
  seed: number;
  partial: boolean;
  note: string;
  total_events: number;
  rules: LiveDetectorScore;
  ml: LiveDetectorScore;
  case_quality: {
    cases_total: number;
    correct: number;
    incorrect: number;
    inconclusive: number;
    awaiting: number;
    unscored: number;
  };
};

export type LiveSnapshot = {
  active: boolean;
  state: string;
  message?: string | null;
  scenarios?: string[];
  summary: LiveSummary | null;
  recent_events: Array<Record<string, unknown>>;
  activity: Array<Record<string, unknown>>;
  alerts: Array<Record<string, unknown>>;
  cases: Array<Record<string, unknown>>;
};

export type DataExplainer = {
  title: string;
  summary: string;
  seed_demo_defaults: {
    duration_hours: number;
    n_accounts: number;
    n_events: number;
    bruteforce_campaigns: number;
    password_spraying_campaigns: number;
    impossible_travel_campaigns: number;
    benign_travelers: number;
  };
  campaign_types: Array<{ id: string; name: string; description: string }>;
  pipeline: string[];
  live_vs_seed: { seed_demo: string; soc_live: string };
};

export const api = {
  health: () => request<{ status: string }>("/api/v1/health"),
  ready: () => request<{ status: string; database: string; investigator: SocSummary["investigator"] }>("/api/v1/ready"),
  summary: () => request<SocSummary>("/api/v1/soc/summary"),
  dataExplainer: () => request<DataExplainer>("/api/v1/soc/data-explainer"),
  seed: (seed = 42) =>
    request<{ dataset_id: string; events: number; cases: number }>("/api/v1/soc/seed", {
      method: "POST",
      body: JSON.stringify({ seed }),
    }),
  cases: (opts?: { scope?: "sites" | "latest" | "live" | "all"; datasetId?: string; limit?: number }) => {
    const params = new URLSearchParams();
    if (opts?.datasetId) {
      params.set("dataset_id", opts.datasetId);
      params.set("limit", String(opts.limit ?? 1000));
    } else {
      params.set("scope", opts?.scope ?? "latest");
      if (opts?.limit) params.set("limit", String(opts.limit));
    }
    return request<CaseSummary[]>(`/api/v1/cases?${params}`);
  },
  caseDetail: (id: string) => request<CaseDetail>(`/api/v1/cases/${id}`),
  investigate: (caseId: string, provider: "mock" | "haiku", idempotencyKey?: string) =>
    request<InvestigationRun>(`/api/v1/cases/${caseId}/investigations`, {
      method: "POST",
      body: JSON.stringify({ provider, idempotency_key: idempotencyKey }),
    }),
  evaluateCase: (caseId: string, runId?: string) => {
    const query = runId ? `?run_id=${encodeURIComponent(runId)}` : "";
    return request<CaseEvaluation>(`/api/v1/cases/${caseId}/evaluate${query}`, { method: "POST" });
  },
  liveStatus: () => request<LiveSnapshot>("/api/v1/live/status"),
  scoreLive: () =>
    request<{ evaluation_id: string; metrics: LiveScore }>("/api/v1/live/score", { method: "POST" }),
  liveControl: (body: Record<string, unknown>) =>
    request<LiveSnapshot>("/api/v1/live/control", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  benchmark: (seed: number, provider: "mock" | "haiku") =>
    request<{ evaluation_id: string; metrics: Record<string, unknown> }>("/api/v1/evaluations/benchmark", {
      method: "POST",
      body: JSON.stringify({ seed, provider }),
    }),
  evaluations: (limit = 50) => request<Array<Record<string, unknown>>>(`/api/v1/evaluations?limit=${limit}`),
  threatScenarios: () => request<ThreatScenario[]>("/api/v1/threat-lab/scenarios"),
  threatRun: (body: { scenario_id?: string; proposal?: boolean }) =>
    request<Record<string, unknown>>("/api/v1/threat-lab/runs", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  demoPath: () => request<DemoPathResponse>("/api/v1/product/demo-path"),
  story: () => request<StoryResponse>("/api/v1/product/story"),
  trust: () => request<TrustResponse>("/api/v1/product/trust"),
  tenants: () => request<PipelineStatus["tenants"]>("/api/v1/product/tenants"),
  pipelineStatus: () => request<PipelineStatus>("/api/v1/pipeline/status"),
};

export type ThreatScenario = {
  scenario_id: string;
  strategy: string;
  description: string;
  seeds: number[];
  tags: string[];
  plan: Record<string, number>;
};

export type DemoPathResponse = {
  title: string;
  pitch: string;
  audience: string;
  presenter_route?: string;
  steps: Array<{ id: string; title: string; route: string; action: string; why: string }>;
  talking_points: string[];
};

export type StoryBeat = {
  id: string;
  kicker: string;
  headline: string;
  line: string;
  blocks: string[];
  say?: string;
  cta?: { label: string; route: string };
};

export type StoryResponse = {
  title: string;
  subtitle: string;
  controls: string;
  beats: StoryBeat[];
};

export type TrustResponse = {
  title: string;
  bullets: Array<{ title: string; text: string }>;
};

export type PipelineStatus = {
  title: string;
  summary: string;
  scope?: {
    persists_cases: boolean;
    runs_ml: boolean;
    runs_rules: boolean;
    exports_metrics: boolean;
    product_case_path: string;
  };
  broker: { kind: string; kafka_api: string; console_url: string; protocol: string };
  observability: {
    prometheus_url: string;
    grafana_url: string;
    worker_metrics_url: string;
    worker_reachable: boolean;
  };
  tenants: Array<{
    tenant_id: string;
    display_name: string;
    region: string;
    kind: string;
    topic: string;
    seed_offset: number;
    description: string;
  }>;
  topics: string[];
  compose_profile: string;
  how_to_run: string[];
  k8s_narrative: string;
};
