import { describe, expect, it } from "vitest";
import { buildCaseResume, summarizeEvents } from "./caseResume";

describe("buildCaseResume", () => {
  it("labels rule-backed bruteforce", () => {
    const resume = buildCaseResume("rule_backed", [
      { rule_id: "bruteforce", severity: "high", event_ids: ["e1"] },
    ]);
    expect(resume.source).toBe("Rules");
    expect(resume.attackGuess).toBe("Brute force");
  });

  it("labels ml-only cases", () => {
    const resume = buildCaseResume("ml_only", [{ event_id: "e2", score: 0.9, threshold: 0.5 }]);
    expect(resume.source).toBe("ML");
    expect(resume.attackGuess).toBe("ML anomaly");
  });
});

describe("summarizeEvents", () => {
  it("counts accounts countries and outcomes", () => {
    const summary = summarizeEvents([
      { account_id: "a", country_code: "US", source_ip: "10.0.0.1", outcome: "failure" },
      { account_id: "a", country_code: "DE", source_ip: "10.0.0.2", outcome: "success" },
      { account_id: "b", country_code: "US", source_ip: "10.0.0.1", outcome: "failure" },
    ]);
    expect(summary.accounts).toBe(2);
    expect(summary.countries).toEqual(["US", "DE"]);
    expect(summary.failures).toBe(2);
    expect(summary.successes).toBe(1);
  });
});
