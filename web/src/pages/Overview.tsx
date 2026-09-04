import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import { StatusBadge } from "../components/ConfidenceBadge";

export default function Overview(): React.JSX.Element {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["overview"],
    queryFn: api.getOverview,
  });

  if (isLoading) {
    return <p className="page-subtitle">Loading…</p>;
  }
  if (isError) {
    return <div className="callout callout--danger">Failed to load overview: {String(error)}</div>;
  }
  if (!data) {
    return <></>;
  }

  const { stats, recent_campaigns: recentCampaigns } = data;

  return (
    <div className="stack">
      <div>
        <h1 className="page-title">Overview</h1>
        <p className="page-subtitle">
          Collection, enrichment, and campaign activity at a glance.
        </p>
      </div>

      <div className="row" style={{ alignItems: "flex-end", gap: 32 }}>
        <div>
          <div className="lead-metric__value mono">{stats.total_indicators.toLocaleString()}</div>
          <div className="lead-metric__label">
            Total indicators across {stats.sources.length} source
            {stats.sources.length === 1 ? "" : "s"}
          </div>
        </div>
        <div className="page-subtitle" style={{ marginBottom: 0 }}>
          {stats.multi_source_indicator_count.toLocaleString()} seen in more than one source,{" "}
          {recentCampaigns.length} campaign{recentCampaigns.length === 1 ? "" : "s"} recently active
        </div>
      </div>

      <div className="doc-section">
        <h3>Indicators by type</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {stats.indicators_by_type.map((row) => (
              <tr key={row.type}>
                <td className="mono">{row.type}</td>
                <td>{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="doc-section">
        <h3>Enrichment coverage</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Total</th>
              <th>Enriched</th>
              <th>Coverage</th>
              <th>Stale</th>
            </tr>
          </thead>
          <tbody>
            {stats.enrichment_coverage.map((row) => (
              <tr key={row.type}>
                <td className="mono">{row.type}</td>
                <td>{row.total}</td>
                <td>{row.enriched}</td>
                <td>{row.coverage_pct.toFixed(0)}%</td>
                <td>{row.stale}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="doc-section">
        <h3>Recent campaign activity</h3>
        {recentCampaigns.length === 0 ? (
          <p className="page-subtitle">No campaigns yet.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Code</th>
                <th>Name</th>
                <th>Status</th>
                <th>Score</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {recentCampaigns.map((campaign) => (
                <tr key={campaign.code}>
                  <td className="mono">
                    <Link to={`/campaigns/${campaign.code}`}>{campaign.code}</Link>
                  </td>
                  <td>{campaign.display_name ?? "-"}</td>
                  <td>
                    <StatusBadge status={campaign.status} />
                  </td>
                  <td>{campaign.score.toFixed(2)}</td>
                  <td>{new Date(campaign.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
