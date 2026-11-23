"""MISP feed export: real, verified MISP type/tag vocabulary (see the
module docstring in `export/misp.py` for what was checked against
upstream MISP data and how), and a small MISP-feed parser fixture that
loads `manifest.json` + per-event files + `hashes.csv` back and checks
they're mutually consistent. Standing in for "loads in a MISP feed
parser" without adding a PyMISP dependency just for this."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ledgerhound.assess.evidence import build_evidence_pack
from ledgerhound.db.models import Assessment, Campaign, CampaignMember, Indicator, IndicatorType
from ledgerhound.export.misp import build_misp_event, write_misp_feed

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _make_indicator(session: Session, itype: IndicatorType, value: str) -> Indicator:
    ind = Indicator(type=itype, value=value, defanged_value=value, first_seen=NOW, last_seen=NOW)
    session.add(ind)
    session.flush()
    return ind


def _make_campaign(session: Session, code: str, members: list[Indicator]) -> Campaign:
    campaign = Campaign(
        code=code,
        status="active",
        score=1.0,
        relation_types=["shares_receiving_wallet"],
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(campaign)
    session.flush()
    for member in members:
        session.add(CampaignMember(campaign_id=campaign.id, indicator_id=member.id, joined_at=NOW))
    session.flush()
    return campaign


def _valid_draft(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "key_judgements": [
            {"statement": "x", "confidence": "moderate", "supporting_evidence_refs": []}
        ],
        "summary": "A crypto scam campaign.",
        "targeting": {"victim_profile": "v", "geographies": [], "impersonated_brands": []},
        "ttps": [{"technique_id": "T1566", "technique_name": "Phishing", "observation": "o"}],
        "financial": {
            "narrative": "n",
            "total_observed_inflow": "0",
            "cashout_venues": [],
            "sanctions_exposure": "none",
        },
        "assessment": "a",
        "attribution": {"claim": None, "confidence": None, "rationale": "r"},
        "outlook": "o",
        "gaps": [],
    }
    base.update(overrides)
    return base


def _load_misp_feed(out_dir: Path) -> dict[str, Any]:
    """A minimal "MISP feed parser": reads manifest.json + every
    referenced event file + hashes.csv, and checks they agree, the
    shape any real MISP feed consumer relies on."""
    manifest = json.loads((out_dir / "manifest.json").read_text())
    events: dict[str, Any] = {}
    for event_uuid in manifest:
        event_path = out_dir / f"{event_uuid}.json"
        assert event_path.is_file(), f"manifest references missing event file {event_path}"
        event = json.loads(event_path.read_text())
        assert event["Event"]["uuid"] == event_uuid
        events[event_uuid] = event

    hashes_rows = list(csv.reader(io.StringIO((out_dir / "hashes.csv").read_text())))
    hashes_by_event: dict[str, set[str]] = {}
    for value_hash, event_uuid in hashes_rows:
        hashes_by_event.setdefault(event_uuid, set()).add(value_hash)

    for event_uuid, event in events.items():
        expected = {
            hashlib.sha256(attr["value"].encode("utf-8")).hexdigest()
            for attr in event["Event"]["Attribute"]
        }
        assert hashes_by_event.get(event_uuid, set()) == expected

    return {"manifest": manifest, "events": events}


def test_misp_event_uses_real_misp_vocabulary(db_session: Session) -> None:
    a = _make_indicator(db_session, IndicatorType.BTC_ADDRESS, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    b = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    campaign = _make_campaign(db_session, "LH-2026-001", [a, b])
    db_session.commit()

    assessment = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash="h",
        prompt_version="v1",
        model="m",
        draft=_valid_draft(),
        status="approved",
        reviewed_by="alice",
        reviewed_at=NOW,
        stale=False,
    )
    db_session.add(assessment)
    db_session.commit()
    pack = build_evidence_pack(db_session, campaign)

    event = build_misp_event(campaign, assessment, pack, tlp="TLP:CLEAR")
    attrs_by_value = {attr["value"]: attr for attr in event["Event"]["Attribute"]}

    # btc is a real, native MISP attribute type; eth has no native MISP
    # cryptocurrency type (only btc/xmr exist) so it must fall back to
    # the real generic `text` type, never an invented "eth" type.
    assert attrs_by_value["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]["type"] == "btc"
    assert attrs_by_value["0xA"]["type"] == "text"

    tag_names = {tag["name"] for tag in event["Event"]["Tag"]}
    assert "tlp:clear" in tag_names
    assert 'estimative-language:confidence-in-analytic-judgment="moderate"' in tag_names
    assert 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"' in tag_names


def test_misp_feed_loads_with_the_parser_fixture(db_session: Session, tmp_path: Path) -> None:
    a = _make_indicator(db_session, IndicatorType.ETH_ADDRESS, "0xA")
    b = _make_indicator(db_session, IndicatorType.DOMAIN, "evil.example")
    campaign_1 = _make_campaign(db_session, "LH-2026-001", [a])
    campaign_2 = _make_campaign(db_session, "LH-2026-002", [b])
    db_session.commit()

    assessments = []
    for campaign in (campaign_1, campaign_2):
        assessment = Assessment(
            campaign_id=campaign.id,
            version=1,
            evidence_hash="h",
            prompt_version="v1",
            model="m",
            draft=_valid_draft(),
            status="approved",
            reviewed_by="alice",
            reviewed_at=NOW,
            stale=False,
        )
        db_session.add(assessment)
        assessments.append(assessment)
    db_session.commit()

    campaigns = [
        (campaign_1, assessments[0], build_evidence_pack(db_session, campaign_1)),
        (campaign_2, assessments[1], build_evidence_pack(db_session, campaign_2)),
    ]
    out_dir = tmp_path / "misp"
    written = write_misp_feed(out_dir, campaigns)

    assert (out_dir / "manifest.json").is_file()
    assert (out_dir / "hashes.csv").is_file()
    assert len([p for p in written if p.suffix == ".json" and p.name != "manifest.json"]) == 2

    loaded = _load_misp_feed(out_dir)
    assert len(loaded["manifest"]) == 2
    assert len(loaded["events"]) == 2

