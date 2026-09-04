"""Static IOC feed: defang-by-default / `--refanged` correctness, and
the shape of every file the static site writes."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ledgerhound.assess.evidence import build_evidence_pack
from ledgerhound.db.models import Assessment, Campaign, CampaignMember, Indicator, IndicatorType
from ledgerhound.export.feed import build_campaign_entry, write_feed

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _make_campaign_with_domain(session: Session) -> tuple[Campaign, Assessment, Any]:
    indicator = Indicator(
        type=IndicatorType.DOMAIN,
        value="evil.example",
        defanged_value="evil[.]example",
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(indicator)
    session.flush()

    campaign = Campaign(
        code="LH-2026-001",
        status="active",
        score=1.0,
        relation_types=["shares_registrar_and_ns"],
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(campaign)
    session.flush()
    session.add(CampaignMember(campaign_id=campaign.id, indicator_id=indicator.id, joined_at=NOW))

    assessment = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash="h",
        prompt_version="v1",
        model="m",
        draft={"summary": "A crypto scam campaign."},
        status="approved",
        reviewed_by="alice",
        reviewed_at=NOW,
        stale=False,
    )
    session.add(assessment)
    session.commit()

    pack = build_evidence_pack(session, campaign)
    return campaign, assessment, pack


def test_defanged_by_default(db_session: Session) -> None:
    campaign, assessment, pack = _make_campaign_with_domain(db_session)
    entry = build_campaign_entry(campaign, assessment, pack)
    assert entry["indicators"][0]["value"] == "evil[.]example"


def test_refanged_option_uses_raw_value(db_session: Session) -> None:
    campaign, assessment, pack = _make_campaign_with_domain(db_session)
    entry = build_campaign_entry(campaign, assessment, pack, refanged=True)
    assert entry["indicators"][0]["value"] == "evil.example"


def test_write_feed_produces_every_expected_file(db_session: Session, tmp_path: Path) -> None:
    campaign, assessment, pack = _make_campaign_with_domain(db_session)
    out_dir = tmp_path / "feed"

    written = write_feed(out_dir, [(campaign, assessment, pack)])
    names = {p.name for p in written}
    assert names == {"LH-2026-001.json", "iocs.json", "iocs.csv", "feed.json", "index.html"}

    campaign_json = json.loads((out_dir / "LH-2026-001.json").read_text())
    assert campaign_json["campaign"] == "LH-2026-001"
    assert campaign_json["indicators"][0]["value"] == "evil[.]example"

    feed_index = json.loads((out_dir / "feed.json").read_text())
    assert feed_index["campaign_count"] == 1
    assert feed_index["campaigns"][0]["campaign"] == "LH-2026-001"

    iocs_json = json.loads((out_dir / "iocs.json").read_text())
    assert iocs_json == [
        {
            "campaign": "LH-2026-001",
            "type": "domain",
            "value": "evil[.]example",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
        }
    ]

    csv_rows = list(csv.DictReader(io.StringIO((out_dir / "iocs.csv").read_text())))
    assert csv_rows == [
        {
            "campaign": "LH-2026-001",
            "type": "domain",
            "value": "evil[.]example",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
        }
    ]

    html = (out_dir / "index.html").read_text()
    assert "LH-2026-001" in html
    assert "active" in html
