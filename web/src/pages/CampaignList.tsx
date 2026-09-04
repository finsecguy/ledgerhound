import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import type { CampaignSummary } from "../api/client";
import { api } from "../api/client";
import { StatusBadge } from "../components/ConfidenceBadge";

type SortKey = "score" | "code" | "last_seen" | "member_count";

export default function CampaignList(): React.JSX.Element {
  const [status, setStatus] = useState<string>("");
  const [minSize, setMinSize] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [sortKey, setSortKey] = useState<SortKey>("score");

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["campaigns", status, minSize, search],
    queryFn: () =>
      api.listCampaigns({
        status: status || undefined,
        min_size: minSize ? Number(minSize) : undefined,
        search: search || undefined,
      }),
  });

  const sorted = useMemo(() => {
    const campaigns = data?.campaigns ?? [];
    return [...campaigns].sort((a, b) => {
      if (sortKey === "score") return b.score - a.score;
      if (sortKey === "member_count") return b.member_count - a.member_count;
      if (sortKey === "last_seen") return b.last_seen.localeCompare(a.last_seen);
      return a.code.localeCompare(b.code);
    });
  }, [data, sortKey]);

  return (
    <div className="stack">
      <div>
        <h1 className="page-title">Campaigns</h1>
        <p className="page-subtitle">{data ? `${data.total} campaign(s)` : "Loading…"}</p>
      </div>

      <div className="row card">
        <div className="field">
          <label htmlFor="search">Search</label>
          <input
            id="search"
            type="search"
            placeholder="code, name, or member value"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="status">Status</label>
          <select id="status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All</option>
            <option value="active">Active</option>
            <option value="dormant">Dormant</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="min-size">Min. size</label>
          <input
            id="min-size"
            type="number"
            min={0}
            value={minSize}
            onChange={(e) => setMinSize(e.target.value)}
            style={{ width: 80 }}
          />
        </div>
        <div className="field">
          <label htmlFor="sort">Sort by</label>
          <select
            id="sort"
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
          >
            <option value="score">Score</option>
            <option value="code">Code</option>
            <option value="last_seen">Last seen</option>
            <option value="member_count">Member count</option>
          </select>
        </div>
      </div>

      {isError && (
        <div className="callout callout--danger">Failed to load campaigns: {String(error)}</div>
      )}

      {!isLoading && !isError && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Code</th>
              <th>Name</th>
              <th>Status</th>
              <th>Score</th>
              <th>Members</th>
              <th>Relations</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((campaign) => (
              <CampaignRow key={campaign.code} campaign={campaign} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function CampaignRow({ campaign }: { campaign: CampaignSummary }): React.JSX.Element {
  return (
    <tr className="clickable">
      <td className="mono">
        <Link to={`/campaigns/${campaign.code}`}>{campaign.code}</Link>
      </td>
      <td>{campaign.display_name ?? "-"}</td>
      <td>
        <StatusBadge status={campaign.status} />
      </td>
      <td>{campaign.score.toFixed(2)}</td>
      <td>{campaign.member_count}</td>
      <td>{campaign.relation_types.join(", ") || "-"}</td>
      <td>{new Date(campaign.last_seen).toLocaleString()}</td>
    </tr>
  );
}
