/** Derive a short dossier resume from detector signals (no ground truth). */

export type CaseSignal = {
  rule_id?: string;
  severity?: string;
  explanation?: string;
  event_ids?: string[];
  event_id?: string;
  score?: number;
  threshold?: number;
  model_run_id?: string;
  signal_id?: string;
};

const ATTACK_LABEL: Record<string, string> = {
  bruteforce: "Brute force",
  password_spraying: "Password spraying",
  impossible_travel: "Impossible travel",
  ml_only: "ML anomaly",
};

export type CaseResume = {
  source: string;
  sourceDetail: string;
  attackGuess: string;
  attackRules: string[];
  severities: string[];
};

export function buildCaseResume(kind: string, signals: CaseSignal[]): CaseResume {
  const ruleIds = [
    ...new Set(signals.map((s) => s.rule_id).filter((id): id is string => Boolean(id))),
  ];
  const hasMl = signals.some((s) => s.rule_id == null && (s.score != null || s.event_id != null));
  const severities = [
    ...new Set(signals.map((s) => s.severity).filter((s): s is string => Boolean(s))),
  ];

  let source = "Unknown";
  let sourceDetail = kind;
  if (kind === "rule_backed" || ruleIds.length > 0) {
    source = "Rules";
    sourceDetail = ruleIds.length ? ruleIds.join(" · ") : "rule-backed case";
    if (hasMl) {
      source = "Rules + ML";
      sourceDetail = `${sourceDetail} · ML overlap`;
    }
  } else if (kind === "ml_only" || hasMl) {
    source = "ML";
    sourceDetail = "supervised baseline flag";
  }

  const attackRules = ruleIds.length ? ruleIds : kind === "ml_only" ? ["ml_only"] : [];
  const attackGuess =
    attackRules.map((id) => ATTACK_LABEL[id] ?? id).join(" + ") || "Unclassified";

  return { source, sourceDetail, attackGuess, attackRules, severities };
}

export function summarizeEvents(
  events: Array<{ account_id: string; country_code: string; source_ip: string; outcome: string }>,
): { accounts: number; countries: string[]; failures: number; successes: number } {
  const accounts = new Set(events.map((e) => e.account_id));
  const countries = [...new Set(events.map((e) => e.country_code))];
  return {
    accounts: accounts.size,
    countries,
    failures: events.filter((e) => e.outcome === "failure").length,
    successes: events.filter((e) => e.outcome === "success").length,
  };
}
