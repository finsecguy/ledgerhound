import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { ApiError, api } from "../api/client";
import { StatusBadge } from "../components/ConfidenceBadge";

interface CampaignFeedIndicator {
  type: string;
  value: string;
  first_seen: string;
  last_seen: string;
}

interface CampaignFeedDetail {
  campaign: string;
  indicators: CampaignFeedIndicator[];
}

/** Best-effort reversal of the backend's own defanging convention
 * (`extract/normalize.py`'s `defang`: http(s) -> hxxp(s), "." -> "[.]")
 *. Display-only, client-side, for the toggle below. The exported files
 * themselves are static (whichever mode `lh export feed` last ran in);
 * this never touches them. */
function refang(value: string): string {
  return value.replace(/hxxps/gi, "https").replace(/hxxp/gi, "http").replace(/\[\.\]/g, ".");
}

async function fetchCampaignFeedDetail(code: string): Promise<CampaignFeedDetail> {
  const response = await fetch(`/api/feed/files/${encodeURIComponent(code)}.json`);
  if (!response.ok) {
    throw new Error(`Failed to load feed detail for ${code}`);
  }
  return (await response.json()) as CampaignFeedDetail;
}

/** Lists published campaigns from the static IOC feed index
 * (`published/feed/feed.json`, written by `lh export feed`), not the
 * live database, so a campaign only appears here once it's actually
 * been exported. */
export default function FeedBrowser(): React.JSX.Element {
  const [refanged, setRefanged] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const feedQuery = useQuery({
    queryKey: ["feed"],
    queryFn: api.getFeedIndex,
    retry: false,
  });

  const detailQuery = useQuery({
    queryKey: ["feed-detail", expanded],
    queryFn: () => fetchCampaignFeedDetail(expanded!),
    enabled: expanded !== null,
  });

  if (feedQuery.isLoading) {
    return <p className="page-subtitle">Loading…</p>;
  }

  if (feedQuery.isError) {
    const isNotFound = feedQuery.error instanceof ApiError && feedQuery.error.status === 404;
    return (
      <div className="stack">
        <h1 className="page-title">IOC Feed</h1>
        <div className="callout callout--info">
          {isNotFound
            ? "No IOC feed has been exported yet. Run `lh export feed`."
            : "Failed to load the feed."}
        </div>
      </div>
    );
  }

  const feed = feedQuery.data;
  if (!feed) {
    return <></>;
  }

  return (
    <div className="stack">
      <div className="row row--between">
        <div>
          <h1 className="page-title">IOC Feed</h1>
          <p className="page-subtitle">{feed.campaign_count} published campaign(s).</p>
        </div>
        <label className="row" style={{ fontWeight: 500, fontSize: 13 }}>
          <input type="checkbox" checked={refanged} onChange={(e) => setRefanged(e.target.checked)} />
          Show refanged (clickable) values
        </label>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Campaign</th>
            <th>Status</th>
            <th>Indicators</th>
            <th>Last seen</th>
            <th>Files</th>
          </tr>
        </thead>
        <tbody>
          {feed.campaigns.map((campaign) => (
            <>
              <tr key={campaign.campaign} className="clickable">
                <td className="mono">
                  <Link to={`/campaigns/${campaign.campaign}`}>{campaign.campaign}</Link>
                </td>
                <td>
                  <StatusBadge status={campaign.status} />
                </td>
                <td>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() =>
                      setExpanded(expanded === campaign.campaign ? null : campaign.campaign)
                    }
                  >
                    {campaign.indicator_count} {expanded === campaign.campaign ? "▲" : "▼"}
                  </button>
                </td>
                <td>{new Date(campaign.last_seen).toLocaleString()}</td>
                <td>
                  <a href={`/api/feed/files/${campaign.campaign}.json`} target="_blank" rel="noreferrer">
                    JSON
                  </a>
                  {" · "}
                  <a href="/api/feed/files/iocs.csv" target="_blank" rel="noreferrer">
                    CSV (all)
                  </a>
                </td>
              </tr>
              {expanded === campaign.campaign && (
                <tr key={`${campaign.campaign}-detail`}>
                  <td colSpan={5}>
                    {detailQuery.isLoading ? (
                      <p className="page-subtitle">Loading indicators…</p>
                    ) : (
                      <ul className="mono" style={{ margin: 0, fontSize: 12 }}>
                        {detailQuery.data?.indicators.map((indicator, index) => (
                          <li key={index}>
                            {indicator.type}: {refanged ? refang(indicator.value) : indicator.value}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  );
}

