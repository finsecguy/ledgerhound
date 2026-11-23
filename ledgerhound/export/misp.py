"""MISP feed export: manifest.json + one JSON file per event + hashes.csv,
the static "feed" format any MISP instance can add as a feed URL (distinct
from the live MISP REST API, which Ledgerhound never talks to).

Attribute type mapping is honest about MISP's real, current type list
(fetched from `MISP/PyMISP`'s bundled `describeTypes.json` and checked
during development): `btc` is a real native MISP attribute type; `domain`
and `url` are real and native. Ethereum/TRON/Solana addresses and
Telegram handles have **no** native MISP cryptocurrency-address type as
of writing (only `btc` and `xmr` exist). Mapping them to an invented
`eth`/`tron`/`sol` type would silently fail import into a real MISP
instance, so they use MISP's generic `text` type instead, with a comment
noting what they actually are.

Tags are real, verified MISP taxonomy values, not invented ones:
- TLP: `tlp:<color>` (MISP/misp-taxonomies `tlp/machinetag.json`).
- Confidence: `estimative-language:confidence-in-analytic-judgment="low|moderate|high"`
  (MISP/misp-taxonomies `estimative-language/machinetag.json`. This
  predicate's values are exactly our vocabulary, verified directly
  against that file rather than assumed).
- ATT&CK: `misp-galaxy:mitre-attack-pattern="<technique name> - <TID>"`
  (MISP/misp-galaxy `clusters/mitre-attack-pattern.json`'s real
  `value` format for each cluster entry).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from ledgerhound.assess.evidence import EvidencePack
from ledgerhound.db.models import Assessment, Campaign

CampaignData = tuple[Campaign, Assessment, EvidencePack]

#: MISP has no native address type for these chains (confirmed against
#: PyMISP's describeTypes.json, only `btc` and `xmr` are native
#: cryptocurrency types). Falling back to `text` rather than an invented
#: type name that a real MISP instance would silently reject on import.
_MISP_ATTRIBUTE_TYPE = {
    "btc_address": "btc",
    "eth_address": "text",
    "tron_address": "text",
    "sol_address": "text",
    "domain": "domain",
    "url": "url",
    "telegram_handle": "text",
}

_ANALYSIS_COMPLETE = "2"
_THREAT_LEVEL_MEDIUM = "2"
_DISTRIBUTION_ALL_COMMUNITIES = "3"


def _event_uuid(campaign: Campaign) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ledgerhound:misp-event:{campaign.code}"))


def _attribute_uuid(campaign: Campaign, member_ref: str) -> str:
    return str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"ledgerhound:misp-attribute:{campaign.code}:{member_ref}")
    )


def build_misp_event(
    campaign: Campaign, assessment: Assessment, pack: EvidencePack, *, tlp: str = "TLP:CLEAR"
) -> dict[str, Any]:
    """Build one MISP event dict (the `{"Event": {...}}` shape used by
    both the feed's per-event files and the MISP REST API) for a
    campaign's approved assessment."""
    draft = assessment.draft
    as_of: datetime = assessment.reviewed_at or campaign.last_seen
    event_id = _event_uuid(campaign)

    attributes: list[dict[str, Any]] = []
    for member in sorted(pack.members, key=lambda m: m.ref):
        misp_type = _MISP_ATTRIBUTE_TYPE.get(member.indicator_type, "text")
        # `text` is a generic fallback for types MISP has no native
        # attribute type for (see the module docstring). Note what the
        # value actually is so an analyst reading the event isn't left
        # guessing at a bare "text" attribute.
        comment = member.indicator_type if misp_type == "text" else ""
        attributes.append(
            {
                "uuid": _attribute_uuid(campaign, member.ref),
                "type": misp_type,
                "category": "Financial fraud"
                if misp_type in ("btc", "text")
                else "Network activity",
                "value": member.value,
                "to_ids": True,
                "comment": comment,
                "timestamp": str(int(as_of.timestamp())),
            }
        )

    tags = [{"name": f"tlp:{tlp.split(':', 1)[1].lower()}"}]
    for judgement in draft.get("key_judgements", []):
        tags.append(
            {
                "name": (
                    "estimative-language:confidence-in-analytic-judgment="
                    f'"{judgement["confidence"]}"'
                )
            }
        )
        break  # one representative confidence tag per event, not one per judgement
    for ttp in draft.get("ttps", []):
        tags.append(
            {
                "name": (
                    f'misp-galaxy:mitre-attack-pattern="{ttp["technique_name"]} - '
                    f'{ttp["technique_id"]}"'
                )
            }
        )

    event = {
        "Event": {
            "uuid": event_id,
            "info": f"{campaign.code}: {draft['summary'][:120]}",
            "date": as_of.date().isoformat(),
            "threat_level_id": _THREAT_LEVEL_MEDIUM,
            "analysis": _ANALYSIS_COMPLETE,
            "distribution": _DISTRIBUTION_ALL_COMMUNITIES,
            "timestamp": str(int(as_of.timestamp())),
            "publish_timestamp": str(int(as_of.timestamp())),
            "Orgc": {"name": "Ledgerhound"},
            "Tag": tags,
            "Attribute": attributes,
        }
    }
    return event


def serialize_event(event: dict[str, Any]) -> bytes:
    return (json.dumps(event, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_manifest_entry(event: dict[str, Any]) -> dict[str, Any]:
    body = event["Event"]
    return {
        "Orgc": body["Orgc"],
        "Tag": body["Tag"],
        "info": body["info"],
        "date": body["date"],
        "analysis": body["analysis"],
        "threat_level_id": body["threat_level_id"],
        "timestamp": body["timestamp"],
        "publish_timestamp": body["publish_timestamp"],
    }


def build_hashes_csv(events: list[dict[str, Any]]) -> bytes:
    """One `<sha256-of-attribute-value>,<event-uuid>` line per attribute
    the MISP feed convention that lets a MISP instance check a hash
    against the feed without downloading every event first."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    rows: list[tuple[str, str]] = []
    for event in events:
        body = event["Event"]
        for attribute in body["Attribute"]:
            value_hash = hashlib.sha256(attribute["value"].encode("utf-8")).hexdigest()
            rows.append((value_hash, body["uuid"]))
    for row in sorted(rows):
        writer.writerow(row)
    return buffer.getvalue().encode("utf-8")


def build_manifest(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {event["Event"]["uuid"]: build_manifest_entry(event) for event in events}


def write_misp_feed(
    out_dir: Path, campaigns: list[CampaignData], *, tlp: str = "TLP:CLEAR"
) -> list[Path]:
    """Write the full MISP feed (manifest.json + one file per event +
    hashes.csv) to `out_dir`. Returns every file path written, sorted."""
    out_dir.mkdir(parents=True, exist_ok=True)
    events = [
        build_misp_event(campaign, assessment, pack, tlp=tlp)
        for campaign, assessment, pack in campaigns
    ]
    events.sort(key=lambda e: e["Event"]["uuid"])

    written: list[Path] = []
    for event in events:
        path = out_dir / f"{event['Event']['uuid']}.json"
        path.write_bytes(serialize_event(event))
        written.append(path)

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(build_manifest(events), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written.append(manifest_path)

    hashes_path = out_dir / "hashes.csv"
    hashes_path.write_bytes(build_hashes_csv(events))
    written.append(hashes_path)

    return sorted(written)

