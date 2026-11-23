import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { GraphEdge, GraphNode } from "../api/client";
import EntityGraph from "../components/EntityGraph";
import EvidencePanel, { type GraphSelection } from "../components/EvidencePanel";
import { StatusBadge } from "../components/ConfidenceBadge";

export default function CampaignDetail(): React.JSX.Element {
  const { code } = useParams<{ code: string }>();
  const queryClient = useQueryClient();
  const [selection, setSelection] = useState<GraphSelection>(null);
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");

  const campaignQuery = useQuery({
    queryKey: ["campaign", code],
    queryFn: () => api.getCampaign(code!),
    enabled: !!code,
  });

  const graphQuery = useQuery({
    queryKey: ["campaign-graph", code],
    queryFn: () => api.getCampaignGraph(code!),
    enabled: !!code,
  });

  const renameMutation = useMutation({
    mutationFn: (displayName: string | null) => api.updateDisplayName(code!, displayName),
    onSuccess: (updated) => {
      queryClient.setQueryData(["campaign", code], updated);
      setEditingName(false);
    },
  });

  async function selectNode(node: GraphNode): Promise<void> {
    setSelection({ kind: "node", node });
    try {
      const indicatorId = node.id.replace(/^member:/, "");
      const explain = await api.explainIndicator(code!, indicatorId);
      setSelection({ kind: "node", node, explain });
    } catch {
      // Selection still shows the node without the explain detail.
    }
  }

  function selectEdge(edge: GraphEdge): void {
    setSelection({ kind: "edge", edge });
  }

  if (!code) {
    return <div className="callout callout--danger">No campaign code in URL.</div>;
  }
  if (campaignQuery.isLoading) {
    return <p className="page-subtitle">Loading…</p>;
  }
  if (campaignQuery.isError || !campaignQuery.data) {
    return <div className="callout callout--danger">Campaign {code} not found.</div>;
  }

  const campaign = campaignQuery.data;
  const assessment = campaign.latest_assessment;

  return (
    <div className="stack">
      <div className="row row--between">
        <div>
          <div className="row">
            <h1 className="page-title mono">{campaign.code}</h1>
            <StatusBadge status={campaign.status} />
          </div>
          {editingName ? (
            <div className="row">
              <input
                type="text"
                value={nameDraft}
                onChange={(e) => setNameDraft(e.target.value)}
                placeholder="Display name"
              />
              <button
                type="button"
                className="primary"
                onClick={() => renameMutation.mutate(nameDraft || null)}
                disabled={renameMutation.isPending}
              >
                Save
              </button>
              <button type="button" className="ghost" onClick={() => setEditingName(false)}>
                Cancel
              </button>
            </div>
          ) : (
            <p
              className="page-subtitle"
              style={{ cursor: "pointer" }}
              onClick={() => {
                setNameDraft(campaign.display_name ?? "");
                setEditingName(true);
              }}
              title="Click to rename"
            >
              {campaign.display_name ?? "(no display name. Click to set one)"}
            </p>
          )}
        </div>
        <div className="stack" style={{ alignItems: "flex-end", gap: 4 }}>
          <div>
            Score: <strong>{campaign.score.toFixed(2)}</strong>
          </div>
          <div className="page-subtitle">
            First seen {new Date(campaign.first_seen).toLocaleDateString()}, last seen{" "}
            {new Date(campaign.last_seen).toLocaleDateString()}
          </div>
        </div>
      </div>

      <div className="row">
        {assessment ? (
          <Link to={`/campaigns/${campaign.code}/assessment`} className="card--link card">
            Assessment: <span className={`badge badge--${assessment.status}`}>{assessment.status}</span>
            {assessment.stale && <span className="badge badge--stale">stale</span>}
            {" "}(v{assessment.version})
          </Link>
        ) : (
          <Link to={`/campaigns/${campaign.code}/assessment`} className="card--link card">
            No assessment yet. Draft one
          </Link>
        )}
        <Link to={`/campaigns/${campaign.code}/report`} className="card--link card">
          View report
        </Link>
      </div>

      <div className="hero-graph">
        <h3>Entity graph</h3>
        <div className="row" style={{ alignItems: "flex-start" }}>
          <div style={{ flex: 3, minWidth: 0 }}>
            {graphQuery.data ? (
              <EntityGraph graph={graphQuery.data} onNodeSelect={selectNode} onEdgeSelect={selectEdge} />
            ) : (
              <p className="page-subtitle">Loading graph…</p>
            )}
          </div>
          <div style={{ flex: 1, minWidth: 220 }}>
            <EvidencePanel selection={selection} onClose={() => setSelection(null)} />
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Members ({campaign.members.length})</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Joined</th>
            </tr>
          </thead>
          <tbody>
            {campaign.members.map((member) => (
              <tr key={member.indicator_id}>
                <td className="mono">{member.type}</td>
                <td className="mono">{member.value}</td>
                <td>{new Date(member.joined_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {campaign.events.length > 0 && (
        <div className="card">
          <h3>Event history</h3>
          <ul className="stack" style={{ gap: 8 }}>
            {campaign.events.map((event, index) => (
              <li key={index} className="row">
                <span className={`badge badge--${event.event_type === "merge" ? "approved" : "in_review"}`}>
                  {event.event_type}
                </span>
                <span>{new Date(event.occurred_at).toLocaleString()}</span>
                <span className="page-subtitle">
                  {event.members_before_count} → {event.members_after_count} members
                  {event.related_campaign_codes.length > 0 &&
                    ` (with ${event.related_campaign_codes.join(", ")})`}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

