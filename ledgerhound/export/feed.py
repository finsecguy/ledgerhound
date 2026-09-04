"""Static IOC feed: per-campaign JSON, a combined `iocs.csv`/`iocs.json`,
a `feed.json` index, and an `index.html` listing — plain files suitable
for GitHub Pages or any static host, no server-side logic required.

Defanged by default (every value comes from `EvidencePack`'s own
`defanged_value`, the same column extraction already computed for every
domain/URL indicator — see `extract/normalize.py`); `--refanged` swaps in
the raw `value` instead. Chain addresses and Telegram handles have
nothing to defang, so `defanged_value == value` for them already — the
switch is a no-op for those rows either way.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from ledgerhound.assess.evidence import EvidencePack
from ledgerhound.db.models import Assessment, Campaign

CampaignData = tuple[Campaign, Assessment, EvidencePack]


def build_campaign_entry(
    campaign: Campaign, assessment: Assessment, pack: EvidencePack, *, refanged: bool = False
) -> dict[str, Any]:
    indicators = [
        {
            "type": member.indicator_type,
            "value": member.value if refanged else member.defanged_value,
            "first_seen": member.first_seen,
            "last_seen": member.last_seen,
        }
        for member in sorted(pack.members, key=lambda m: m.ref)
    ]
    return {
        "campaign": campaign.code,
        "display_name": campaign.display_name,
        "status": campaign.status,
        "last_seen": campaign.last_seen.isoformat(),
        "summary": assessment.draft["summary"],
        "indicator_count": len(indicators),
        "indicators": indicators,
    }


def build_combined_iocs(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten every campaign entry's indicators into one list, each row
    tagged with its campaign code — the source for both `iocs.json` and
    `iocs.csv`."""
    rows: list[dict[str, Any]] = []
    for entry in entries:
        for indicator in entry["indicators"]:
            rows.append({"campaign": entry["campaign"], **indicator})
    rows.sort(key=lambda r: (r["campaign"], r["type"], r["value"]))
    return rows


def render_iocs_csv(rows: list[dict[str, Any]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=["campaign", "type", "value", "first_seen", "last_seen"]
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue().encode("utf-8")


def build_feed_index(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "campaign_count": len(entries),
        "campaigns": [
            {
                "campaign": e["campaign"],
                "status": e["status"],
                "last_seen": e["last_seen"],
                "indicator_count": e["indicator_count"],
            }
            for e in sorted(entries, key=lambda e: e["campaign"])
        ],
    }


def render_index_html(entries: list[dict[str, Any]]) -> str:
    rows = "\n".join(
        f"    <tr><td>{e['campaign']}</td><td>{e['display_name'] or '-'}</td>"
        f"<td>{e['status']}</td><td>{e['indicator_count']}</td>"
        f"<td>{e['last_seen']}</td>"
        f'<td><a href="{e["campaign"]}.json">JSON</a></td></tr>'
        for e in sorted(entries, key=lambda e: e["campaign"])
    )
    return (
        '<!doctype html>\n<html><head><meta charset="utf-8">'
        "<title>Ledgerhound IOC feed</title></head><body>\n"
        '<h1>Ledgerhound IOC feed</h1>\n<table border="1" cellpadding="4">\n'
        "  <tr><th>Campaign</th><th>Name</th><th>Status</th>"
        "<th>Indicators</th><th>Last seen</th><th>Detail</th></tr>\n"
        f"{rows}\n</table>\n</body></html>\n"
    )


def write_feed(
    out_dir: Path, campaigns: list[CampaignData], *, refanged: bool = False
) -> list[Path]:
    """Write the full static feed to `out_dir`. Returns every file path
    written, sorted, for the caller to hash/report on."""
    out_dir.mkdir(parents=True, exist_ok=True)
    entries = [
        build_campaign_entry(campaign, assessment, pack, refanged=refanged)
        for campaign, assessment, pack in campaigns
    ]
    entries.sort(key=lambda e: e["campaign"])

    written: list[Path] = []
    for entry in entries:
        path = out_dir / f"{entry['campaign']}.json"
        path.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)

    combined_rows = build_combined_iocs(entries)
    iocs_json_path = out_dir / "iocs.json"
    iocs_json_path.write_text(
        json.dumps(combined_rows, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written.append(iocs_json_path)

    iocs_csv_path = out_dir / "iocs.csv"
    iocs_csv_path.write_bytes(render_iocs_csv(combined_rows))
    written.append(iocs_csv_path)

    feed_json_path = out_dir / "feed.json"
    feed_json_path.write_text(
        json.dumps(build_feed_index(entries), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written.append(feed_json_path)

    index_html_path = out_dir / "index.html"
    index_html_path.write_text(render_index_html(entries), encoding="utf-8")
    written.append(index_html_path)

    return sorted(written)
