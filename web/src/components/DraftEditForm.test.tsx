import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AssessmentDraft, AttackTechniqueOut } from "../api/client";
import DraftEditForm from "./DraftEditForm";

const BASE_DRAFT: AssessmentDraft = {
  key_judgements: [{ statement: "Shares a wallet.", confidence: "high", supporting_evidence_refs: [] }],
  summary: "A crypto scam campaign.",
  targeting: { victim_profile: "retail crypto users", geographies: [], impersonated_brands: [] },
  ttps: [],
  financial: {
    narrative: "Funds moved through a shared wallet.",
    total_observed_inflow: "100",
    cashout_venues: [],
    sanctions_exposure: "none",
  },
  assessment: "Likely a single operator.",
  attribution: { claim: null, confidence: null, rationale: "insufficient evidence" },
  outlook: "Likely to continue.",
  gaps: [],
};

const KNOWN_TECHNIQUES: AttackTechniqueOut[] = [{ technique_id: "T1566", name: "Phishing" }];

describe("DraftEditForm", () => {
  it("rejects an unknown ATT&CK technique id client-side, before calling onSubmit", () => {
    const onSubmit = vi.fn();
    render(
      <DraftEditForm
        initialDraft={{ ...BASE_DRAFT, ttps: [{ technique_id: "T1566", technique_name: "Phishing", observation: "o" }] }}
        evidenceDescriptions={{}}
        attackTechniques={KNOWN_TECHNIQUES}
        serverErrors={[]}
        submitting={false}
        onSubmit={onSubmit}
      />,
    );

    const techniqueInput = screen.getByTestId("ttp-technique-id-0");
    fireEvent.change(techniqueInput, { target: { value: "T9999" } });
    fireEvent.click(screen.getByTestId("draft-submit"));

    expect(screen.getByTestId("draft-form-errors")).toHaveTextContent("Unknown ATT&CK technique id: T9999");
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("submits successfully when every technique id is known", () => {
    const onSubmit = vi.fn();
    render(
      <DraftEditForm
        initialDraft={{ ...BASE_DRAFT, ttps: [{ technique_id: "T1566", technique_name: "Phishing", observation: "o" }] }}
        evidenceDescriptions={{}}
        attackTechniques={KNOWN_TECHNIQUES}
        serverErrors={[]}
        submitting={false}
        onSubmit={onSubmit}
      />,
    );

    fireEvent.click(screen.getByTestId("draft-submit"));

    expect(screen.queryByTestId("draft-form-errors")).not.toBeInTheDocument();
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it("displays server-side validation errors passed in via props (e.g. after a failed save)", () => {
    render(
      <DraftEditForm
        initialDraft={BASE_DRAFT}
        evidenceDescriptions={{}}
        attackTechniques={KNOWN_TECHNIQUES}
        serverErrors={["financial.total_observed_inflow '999' does not match the evidence pack's computed value '100'"]}
        submitting={false}
        onSubmit={vi.fn()}
      />,
    );

    expect(screen.getByTestId("draft-form-errors")).toHaveTextContent("does not match");
  });

  it("adds a new, initially-unknown TTP row via the add-technique button", () => {
    render(
      <DraftEditForm
        initialDraft={BASE_DRAFT}
        evidenceDescriptions={{}}
        attackTechniques={KNOWN_TECHNIQUES}
        serverErrors={[]}
        submitting={false}
        onSubmit={vi.fn()}
      />,
    );

    expect(screen.queryByTestId("ttp-technique-id-0")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("add-ttp"));
    expect(screen.getByTestId("ttp-technique-id-0")).toBeInTheDocument();
  });
});
