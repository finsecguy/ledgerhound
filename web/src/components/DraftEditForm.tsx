import { useState } from "react";

import type { AssessmentDraft, AttackTechniqueOut, Confidence, KeyJudgement, Ttp } from "../api/client";
import { CONFIDENCE_VALUES } from "../api/client";

interface DraftEditFormProps {
  initialDraft: AssessmentDraft;
  evidenceDescriptions: Record<string, string>;
  attackTechniques: AttackTechniqueOut[];
  serverErrors: string[];
  submitting: boolean;
  onSubmit: (draft: AssessmentDraft) => void;
}

function ConfidenceSelect({
  value,
  onChange,
}: {
  value: Confidence;
  onChange: (value: Confidence) => void;
}): React.JSX.Element {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as Confidence)}>
      {CONFIDENCE_VALUES.map((confidence) => (
        <option key={confidence} value={confidence}>
          {confidence}
        </option>
      ))}
    </select>
  );
}

/** The milestone 4 CLI review workflow (`lh assess edit`), as a
 * structured form: confidence is always a dropdown constrained to the
 * backend's exact enum (never free text), evidence refs are picked from
 * the actual evidence pack rather than typed by hand, and ATT&CK
 * technique ids are checked against the cached dataset client-side
 * before submit — a courtesy that mirrors, but never replaces, the
 * server's own `assess/drafter.py` validation on save. */
export default function DraftEditForm({
  initialDraft,
  evidenceDescriptions,
  attackTechniques,
  serverErrors,
  submitting,
  onSubmit,
}: DraftEditFormProps): React.JSX.Element {
  const [draft, setDraft] = useState<AssessmentDraft>(initialDraft);
  const [clientErrors, setClientErrors] = useState<string[]>([]);

  const evidenceRefs = Object.keys(evidenceDescriptions).sort();
  const validTechniqueIds = new Set(attackTechniques.map((t) => t.technique_id));
  const techniqueNameById = new Map(attackTechniques.map((t) => [t.technique_id, t.name]));

  function updateJudgement(index: number, patch: Partial<KeyJudgement>): void {
    setDraft((prev) => ({
      ...prev,
      key_judgements: prev.key_judgements.map((kj, i) => (i === index ? { ...kj, ...patch } : kj)),
    }));
  }

  function toggleJudgementRef(index: number, ref: string): void {
    setDraft((prev) => ({
      ...prev,
      key_judgements: prev.key_judgements.map((kj, i) => {
        if (i !== index) return kj;
        const refs = kj.supporting_evidence_refs ?? [];
        const next = refs.includes(ref) ? refs.filter((r) => r !== ref) : [...refs, ref];
        return { ...kj, supporting_evidence_refs: next };
      }),
    }));
  }

  function addJudgement(): void {
    setDraft((prev) => ({
      ...prev,
      key_judgements: [
        ...prev.key_judgements,
        { statement: "", confidence: "low", supporting_evidence_refs: [] },
      ],
    }));
  }

  function removeJudgement(index: number): void {
    setDraft((prev) => ({
      ...prev,
      key_judgements: prev.key_judgements.filter((_, i) => i !== index),
    }));
  }

  function updateTtp(index: number, patch: Partial<Ttp>): void {
    setDraft((prev) => ({
      ...prev,
      ttps: (prev.ttps ?? []).map((ttp, i) => (i === index ? { ...ttp, ...patch } : ttp)),
    }));
  }

  function addTtp(): void {
    setDraft((prev) => ({
      ...prev,
      ttps: [...(prev.ttps ?? []), { technique_id: "", technique_name: "", observation: "" }],
    }));
  }

  function removeTtp(index: number): void {
    setDraft((prev) => ({ ...prev, ttps: (prev.ttps ?? []).filter((_, i) => i !== index) }));
  }

  function handleTechniqueIdChange(index: number, technique_id: string): void {
    const name = techniqueNameById.get(technique_id);
    updateTtp(index, { technique_id, ...(name ? { technique_name: name } : {}) });
  }

  function handleSubmit(event: React.FormEvent): void {
    event.preventDefault();
    const errors: string[] = [];
    for (const ttp of draft.ttps ?? []) {
      if (ttp.technique_id && !validTechniqueIds.has(ttp.technique_id)) {
        errors.push(`Unknown ATT&CK technique id: ${ttp.technique_id}`);
      }
    }
    setClientErrors(errors);
    if (errors.length > 0) {
      return;
    }
    onSubmit(draft);
  }

  const allErrors = [...clientErrors, ...serverErrors];

  return (
    <form className="stack" onSubmit={handleSubmit} data-testid="draft-edit-form">
      {allErrors.length > 0 && (
        <div className="callout callout--danger" data-testid="draft-form-errors">
          <strong>Cannot save:</strong>
          <ul>
            {allErrors.map((err, index) => (
              <li key={index}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      <section className="card stack">
        <div className="row row--between">
          <h3>Key judgements</h3>
          <button type="button" className="ghost" onClick={addJudgement}>
            + Add judgement
          </button>
        </div>
        {draft.key_judgements.map((judgement, index) => (
          <div key={index} className="stack" style={{ borderTop: "1px solid var(--line)", paddingTop: 10 }}>
            <div className="row">
              <ConfidenceSelect
                value={judgement.confidence}
                onChange={(confidence) => updateJudgement(index, { confidence })}
              />
              <button type="button" className="ghost" onClick={() => removeJudgement(index)}>
                Remove
              </button>
            </div>
            <textarea
              value={judgement.statement}
              onChange={(e) => updateJudgement(index, { statement: e.target.value })}
              placeholder="Statement"
            />
            <div className="field">
              <label>Supporting evidence</label>
              <div className="stack" style={{ maxHeight: 120, overflowY: "auto", gap: 2 }}>
                {evidenceRefs.map((ref) => (
                  <label key={ref} className="row" style={{ gap: 6, fontWeight: 400 }}>
                    <input
                      type="checkbox"
                      checked={(judgement.supporting_evidence_refs ?? []).includes(ref)}
                      onChange={() => toggleJudgementRef(index, ref)}
                    />
                    <span className="mono" style={{ fontSize: 12 }}>
                      {evidenceDescriptions[ref]}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        ))}
      </section>

      <section className="card field">
        <label htmlFor="summary">Summary</label>
        <textarea
          id="summary"
          value={draft.summary}
          onChange={(e) => setDraft((prev) => ({ ...prev, summary: e.target.value }))}
        />
      </section>

      <section className="card stack">
        <h3>Targeting</h3>
        <div className="field">
          <label htmlFor="victim-profile">Victim profile</label>
          <input
            id="victim-profile"
            type="text"
            value={draft.targeting.victim_profile}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                targeting: { ...prev.targeting, victim_profile: e.target.value },
              }))
            }
          />
        </div>
        <div className="field">
          <label htmlFor="geographies">Geographies (comma-separated)</label>
          <input
            id="geographies"
            type="text"
            value={(draft.targeting.geographies ?? []).join(", ")}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                targeting: {
                  ...prev.targeting,
                  geographies: e.target.value
                    .split(",")
                    .map((v) => v.trim())
                    .filter(Boolean),
                },
              }))
            }
          />
        </div>
        <div className="field">
          <label htmlFor="brands">Impersonated brands (comma-separated)</label>
          <input
            id="brands"
            type="text"
            value={(draft.targeting.impersonated_brands ?? []).join(", ")}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                targeting: {
                  ...prev.targeting,
                  impersonated_brands: e.target.value
                    .split(",")
                    .map((v) => v.trim())
                    .filter(Boolean),
                },
              }))
            }
          />
        </div>
      </section>

      <section className="card stack">
        <div className="row row--between">
          <h3>Tradecraft (MITRE ATT&amp;CK)</h3>
          <button type="button" className="ghost" data-testid="add-ttp" onClick={addTtp}>
            + Add technique
          </button>
        </div>
        <datalist id="attack-techniques">
          {attackTechniques.map((t) => (
            <option key={t.technique_id} value={t.technique_id}>
              {t.name}
            </option>
          ))}
        </datalist>
        {(draft.ttps ?? []).map((ttp, index) => {
          const isUnknown = ttp.technique_id !== "" && !validTechniqueIds.has(ttp.technique_id);
          return (
            <div key={index} className="row" style={{ alignItems: "flex-start" }}>
              <div className="field">
                <label>Technique ID</label>
                <input
                  data-testid={`ttp-technique-id-${index}`}
                  list="attack-techniques"
                  type="text"
                  className={isUnknown ? "has-error" : ""}
                  value={ttp.technique_id}
                  onChange={(e) => handleTechniqueIdChange(index, e.target.value)}
                  style={{ width: 140 }}
                />
                {isUnknown && <span className="field-error">Unknown technique id</span>}
              </div>
              <div className="field" style={{ flex: 1 }}>
                <label>Observation</label>
                <input
                  type="text"
                  value={ttp.observation}
                  onChange={(e) => updateTtp(index, { observation: e.target.value })}
                />
              </div>
              <button type="button" className="ghost" onClick={() => removeTtp(index)}>
                Remove
              </button>
            </div>
          );
        })}
      </section>

      <section className="card stack">
        <h3>Financial analysis</h3>
        <div className="field">
          <label htmlFor="financial-narrative">Narrative</label>
          <textarea
            id="financial-narrative"
            value={draft.financial.narrative}
            onChange={(e) =>
              setDraft((prev) => ({ ...prev, financial: { ...prev.financial, narrative: e.target.value } }))
            }
          />
        </div>
        <div className="field">
          <label>Total observed inflow</label>
          <input type="text" className="mono" value={draft.financial.total_observed_inflow} disabled />
          <span className="page-subtitle">
            Computed from the evidence pack — not editable; the server rejects any other value.
          </span>
        </div>
        <div className="field">
          <label htmlFor="sanctions">Sanctions exposure</label>
          <input
            id="sanctions"
            type="text"
            value={draft.financial.sanctions_exposure}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                financial: { ...prev.financial, sanctions_exposure: e.target.value },
              }))
            }
          />
        </div>
      </section>

      <section className="card stack">
        <h3>Assessment</h3>
        <textarea
          value={draft.assessment}
          onChange={(e) => setDraft((prev) => ({ ...prev, assessment: e.target.value }))}
        />
      </section>

      <section className="card stack">
        <h3>Attribution</h3>
        <div className="field">
          <label htmlFor="attribution-claim">Claim (leave blank for unattributed)</label>
          <input
            id="attribution-claim"
            type="text"
            value={draft.attribution.claim ?? ""}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                attribution: { ...prev.attribution, claim: e.target.value || null },
              }))
            }
          />
        </div>
        <div className="field">
          <label>Confidence</label>
          <select
            value={draft.attribution.confidence ?? ""}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                attribution: {
                  ...prev.attribution,
                  confidence: (e.target.value || null) as Confidence | null,
                },
              }))
            }
          >
            <option value="">(none)</option>
            {CONFIDENCE_VALUES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <span className="page-subtitle">
            The server rejects a claim unless at least one key judgement above is "high" confidence.
          </span>
        </div>
        <div className="field">
          <label htmlFor="attribution-rationale">Rationale</label>
          <textarea
            id="attribution-rationale"
            value={draft.attribution.rationale}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                attribution: { ...prev.attribution, rationale: e.target.value },
              }))
            }
          />
        </div>
      </section>

      <section className="card stack">
        <h3>Outlook</h3>
        <textarea
          value={draft.outlook}
          onChange={(e) => setDraft((prev) => ({ ...prev, outlook: e.target.value }))}
        />
      </section>

      <section className="card field">
        <label htmlFor="gaps">Gaps (one per line)</label>
        <textarea
          id="gaps"
          value={(draft.gaps ?? []).join("\n")}
          onChange={(e) =>
            setDraft((prev) => ({
              ...prev,
              gaps: e.target.value.split("\n").filter((line) => line.trim() !== ""),
            }))
          }
        />
      </section>

      <button type="submit" className="primary" data-testid="draft-submit" disabled={submitting}>
        {submitting ? "Saving…" : "Save as new version"}
      </button>
    </form>
  );
}
