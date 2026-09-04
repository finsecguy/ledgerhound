import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router-dom";

import { ApiError, api } from "../api/client";
import type { AssessmentDraft } from "../api/client";
import ConfidenceBadge, { StatusBadge } from "../components/ConfidenceBadge";
import DraftEditForm from "../components/DraftEditForm";
import VersionDiff from "../components/VersionDiff";

type Mode = "view" | "edit" | "diff";

export default function AssessmentReview(): React.JSX.Element {
  const { code } = useParams<{ code: string }>();
  const queryClient = useQueryClient();
  const [version, setVersion] = useState<number | undefined>(undefined);
  const [mode, setMode] = useState<Mode>("view");
  const [diffFrom, setDiffFrom] = useState<number | undefined>(undefined);
  const [diffTo, setDiffTo] = useState<number | undefined>(undefined);
  const [reviewNotes, setReviewNotes] = useState("");
  const [saveErrors, setSaveErrors] = useState<string[]>([]);

  const assessmentQuery = useQuery({
    queryKey: ["assessment", code, version],
    queryFn: () => api.getAssessment(code!, version),
    enabled: !!code,
  });
  const versionsQuery = useQuery({
    queryKey: ["assessment-versions", code],
    queryFn: () => api.listAssessmentVersions(code!),
    enabled: !!code,
  });
  const attackQuery = useQuery({
    queryKey: ["attack-techniques"],
    queryFn: api.listAttackTechniques,
    staleTime: Infinity,
  });
  const diffQuery = useQuery({
    queryKey: ["assessment-diff", code, diffFrom, diffTo],
    queryFn: () => api.diffAssessment(code!, diffFrom!, diffTo!),
    enabled: mode === "diff" && diffFrom !== undefined && diffTo !== undefined,
  });

  function invalidate(): void {
    queryClient.invalidateQueries({ queryKey: ["assessment", code] });
    queryClient.invalidateQueries({ queryKey: ["assessment-versions", code] });
    queryClient.invalidateQueries({ queryKey: ["campaign", code] });
  }

  const draftMutation = useMutation({
    mutationFn: () => api.createDraft(code!, false),
    onSuccess: (result) => {
      setVersion(result.version);
      invalidate();
    },
  });

  const editMutation = useMutation({
    mutationFn: (draft: AssessmentDraft) => api.editAssessment(code!, assessmentQuery.data!.version, draft),
    onSuccess: (result) => {
      setSaveErrors([]);
      setVersion(result.version);
      setMode("view");
      invalidate();
    },
    onError: (err: unknown) => {
      setSaveErrors(err instanceof ApiError ? err.errors : ["Failed to save."]);
    },
  });

  const approveMutation = useMutation({
    mutationFn: () => api.approveAssessment(code!, assessmentQuery.data!.version, reviewNotes),
    onSuccess: () => {
      setReviewNotes("");
      invalidate();
    },
  });

  const rejectMutation = useMutation({
    mutationFn: () => api.rejectAssessment(code!, assessmentQuery.data!.version, reviewNotes),
    onSuccess: () => {
      setReviewNotes("");
      invalidate();
    },
  });

  if (!code) {
    return <div className="callout callout--danger">No campaign code in URL.</div>;
  }

  if (assessmentQuery.isError) {
    const isNotFound = assessmentQuery.error instanceof ApiError && assessmentQuery.error.status === 404;
    return (
      <div className="stack">
        <h1 className="page-title mono">{code}: Assessment</h1>
        {isNotFound ? (
          <div className="callout callout--info">
            No assessment yet for this campaign.
            <div style={{ marginTop: 8 }}>
              <button
                type="button"
                className="primary"
                onClick={() => draftMutation.mutate()}
                disabled={draftMutation.isPending}
              >
                {draftMutation.isPending ? "Drafting…" : "Draft with LLM"}
              </button>
            </div>
            {draftMutation.isError && (
              <p className="field-error">
                {draftMutation.error instanceof ApiError
                  ? draftMutation.error.errors.join("; ")
                  : "Failed to draft."}
              </p>
            )}
          </div>
        ) : (
          <div className="callout callout--danger">Failed to load assessment.</div>
        )}
      </div>
    );
  }

  if (assessmentQuery.isLoading || !assessmentQuery.data) {
    return <p className="page-subtitle">Loading…</p>;
  }

  const assessment = assessmentQuery.data;
  const versions = versionsQuery.data ?? [];
  const attackTechniques = attackQuery.data?.techniques ?? [];
  const canApprove = assessment.status === "draft" || assessment.status === "in_review";
  const canReject = assessment.status !== "rejected";

  return (
    <div className="stack">
      <div className="row row--between">
        <div>
          <h1 className="page-title mono">{code}: Assessment</h1>
          <div className="row">
            <StatusBadge status={assessment.status} />
            {assessment.stale && (
              <span className="badge badge--stale" title="Evidence has changed since approval">
                stale — re-review before publishing
              </span>
            )}
            <span className="page-subtitle">v{assessment.version}</span>
            {assessment.edited_by_human && <span className="page-subtitle">(human-edited)</span>}
          </div>
        </div>
        <div className="row">
          <select
            value={version ?? assessment.version}
            onChange={(e) => setVersion(Number(e.target.value))}
          >
            {versions.map((v) => (
              <option key={v.version} value={v.version}>
                v{v.version} — {v.status}
              </option>
            ))}
          </select>
          <button type="button" onClick={() => setMode(mode === "edit" ? "view" : "edit")}>
            {mode === "edit" ? "Cancel edit" : "Edit"}
          </button>
          <button
            type="button"
            onClick={() => {
              setMode("diff");
              setDiffFrom(versions[0]?.version);
              setDiffTo(assessment.version);
            }}
          >
            Diff versions
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => draftMutation.mutate()}
            disabled={draftMutation.isPending}
          >
            Re-draft
          </button>
        </div>
      </div>

      {mode === "diff" && (
        <div className="card stack">
          <div className="row">
            <select value={diffFrom ?? ""} onChange={(e) => setDiffFrom(Number(e.target.value))}>
              {versions.map((v) => (
                <option key={v.version} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </select>
            <span>vs</span>
            <select value={diffTo ?? ""} onChange={(e) => setDiffTo(Number(e.target.value))}>
              {versions.map((v) => (
                <option key={v.version} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </select>
          </div>
          {diffQuery.data && <VersionDiff unifiedDiff={diffQuery.data.unified_diff} />}
        </div>
      )}

      {mode === "edit" ? (
        <DraftEditForm
          initialDraft={assessment.draft}
          evidenceDescriptions={assessment.evidence_ref_descriptions}
          attackTechniques={attackTechniques}
          serverErrors={saveErrors}
          submitting={editMutation.isPending}
          onSubmit={(draft) => editMutation.mutate(draft)}
        />
      ) : (
        <div className="row" style={{ alignItems: "flex-start" }}>
          <div className="stack" style={{ flex: 2 }}>
            <div className="doc-section stack">
              <h3>Key judgements</h3>
              {assessment.draft.key_judgements.map((kj, index) => (
                <div key={index} className="row" style={{ alignItems: "flex-start" }}>
                  <ConfidenceBadge confidence={kj.confidence} />
                  <span>{kj.statement}</span>
                </div>
              ))}
            </div>
            <div className="doc-section">
              <h3>Summary</h3>
              <p>{assessment.draft.summary}</p>
            </div>
            <div className="doc-section">
              <h3>Targeting</h3>
              <p>{assessment.draft.targeting.victim_profile}</p>
              <p className="page-subtitle">
                Geographies: {(assessment.draft.targeting.geographies ?? []).join(", ") || "none"}.{" "}
                Brands impersonated: {(assessment.draft.targeting.impersonated_brands ?? []).join(", ") || "none"}.
              </p>
            </div>
            <div className="doc-section">
              <h3>Tradecraft</h3>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Technique</th>
                    <th>Observation</th>
                  </tr>
                </thead>
                <tbody>
                  {(assessment.draft.ttps ?? []).map((ttp, index) => (
                    <tr key={index}>
                      <td className="mono">
                        {ttp.technique_id} — {ttp.technique_name}
                      </td>
                      <td>{ttp.observation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="doc-section">
              <h3>Financial analysis</h3>
              <p>{assessment.draft.financial.narrative}</p>
              <p className="page-subtitle mono">
                Total observed inflow: {assessment.draft.financial.total_observed_inflow}
              </p>
            </div>
            <div className="doc-section">
              <h3>Assessment</h3>
              <p>{assessment.draft.assessment}</p>
            </div>
            <div className="doc-section">
              <h3>Attribution</h3>
              <div className="row">
                <span>{assessment.draft.attribution.claim ?? "Unattributed"}</span>
                <ConfidenceBadge confidence={assessment.draft.attribution.confidence} />
              </div>
              <p className="page-subtitle">{assessment.draft.attribution.rationale}</p>
            </div>
            <div className="doc-section">
              <h3>Outlook</h3>
              <p>{assessment.draft.outlook}</p>
              {(assessment.draft.gaps ?? []).length > 0 && (
                <>
                  <h4>Gaps</h4>
                  <ul>
                    {(assessment.draft.gaps ?? []).map((gap, index) => (
                      <li key={index}>{gap}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          </div>

          <div className="stack" style={{ flex: 1 }}>
            <div className="card">
              <h3>Evidence pack</h3>
              <div className="stack" style={{ maxHeight: 400, overflowY: "auto", gap: 4 }}>
                {Object.entries(assessment.evidence_ref_descriptions).map(([ref, description]) => (
                  <div key={ref} style={{ fontSize: 12 }}>
                    <span className="mono page-subtitle">{ref}</span>
                    <div>{description}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="card stack">
              <h3>Review</h3>
              {assessment.stale && (
                <div className="callout callout--warning">
                  This assessment's evidence has changed since it was last reviewed. Re-draft or
                  edit before approving.
                </div>
              )}
              <textarea
                placeholder="Review notes (required)"
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
              />
              <div className="review-bar">
                <p className="review-bar__consequence">
                  Approving publishes this as the campaign's official assessment. Rejecting closes
                  this version out — a new draft is needed to try again. Both require review notes.
                </p>
                <div className="row">
                  <button
                    type="button"
                    className="primary"
                    disabled={!canApprove || !reviewNotes.trim() || approveMutation.isPending}
                    onClick={() => approveMutation.mutate()}
                  >
                    {approveMutation.isPending ? "Approving…" : "Approve"}
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={!canReject || !reviewNotes.trim() || rejectMutation.isPending}
                    onClick={() => rejectMutation.mutate()}
                  >
                    {rejectMutation.isPending ? "Rejecting…" : "Reject"}
                  </button>
                </div>
              </div>
              {assessment.reviewed_by && (
                <p className="page-subtitle">
                  Last reviewed by {assessment.reviewed_by} on{" "}
                  {assessment.reviewed_at && new Date(assessment.reviewed_at).toLocaleString()}:{" "}
                  {assessment.reviewer_notes}
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
