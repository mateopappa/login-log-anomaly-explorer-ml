import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ProviderBadge } from "./ProviderBadge";

describe("ProviderBadge", () => {
  it("labels mock runs clearly", () => {
    render(<ProviderBadge mode="mock" providerId="deterministic-case-mock-v1" />);
    expect(screen.getByText(/Mock baseline/i)).toBeInTheDocument();
  });

  it("labels Claude Haiku runs with model when present", () => {
    render(<ProviderBadge mode="llm" providerId="anthropic-haiku" model="claude-haiku-5-5" />);
    expect(screen.getByText(/Claude Haiku/i)).toBeInTheDocument();
    expect(screen.getByText(/claude-haiku-5-5/i)).toBeInTheDocument();
  });
});
