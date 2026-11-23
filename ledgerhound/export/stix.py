"""STIX 2.1 bundle export for one campaign's approved assessment.

Uses the `stix2` library for every standard SDO (identity, campaign,
indicator, relationship, report). TLP 2.0 markings and their extension-
definition object are hand-built dicts instead: `stix2` 3.0.2 predates
OASIS's 2022 TLP-2.0-as-an-extension-definition mechanism and only ships
the older TLP 1.0 constants (WHITE/GREEN/AMBER/RED), so the five real,
well-known TLP 2.0 objects below are vendored verbatim from
`oasis-open/cti-stix-common-objects` (fetched and diffed against that
repo during development) rather than approximated.

Determinism: every object's `id` is a UUIDv5 derived from stable content
(campaign code, indicator type+value, technique id, ...), not `uuid4()`.
`created`/`modified`/`published` are all pinned to the published
assessment's `reviewed_at` (when it was approved), not wall-clock export
time, the same approved assessment always produces the same bundle
bytes. `stix2-validator` flags non-v4 ids as a "SHOULD" warning (check
103), never an error; determinism is worth that trade.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

import stix2

from ledgerhound import __author__ as PRODUCT_AUTHOR
from ledgerhound.assess.attack import AttackDataset
from ledgerhound.assess.drafter import overall_confidence
from ledgerhound.assess.evidence import EvidencePack
from ledgerhound.db.models import Assessment, Campaign

STIX_SPEC_VERSION = "2.1"

#: STIX 2.1 defines confidence as an integer 0-100 with a *non-normative*
#: example scale; there is no single official mapping from a 3-level
#: low/moderate/high vocabulary onto it. These are Ledgerhound's own
#: representative points on that scale, not a literal OASIS table.
CONFIDENCE_SCALE: dict[str, int] = {"low": 25, "moderate": 50, "high": 75}

_CHAIN_INDICATOR_TYPES = {"btc_address", "eth_address", "tron_address", "sol_address"}
_CHAIN_BY_INDICATOR_TYPE = {
    "btc_address": "btc",
    "eth_address": "eth",
    "tron_address": "tron",
    "sol_address": "sol",
}

# --- TLP 2.0: vendored verbatim from oasis-open/cti-stix-common-objects ----
# (objects/marking-definition/marking-definition--<id>.json, and the TLP 2.0
# extension-definition they all reference), since stix2 3.0.2 doesn't ship
# these. Every real-world TLP 2.0 producer/consumer recognizes these exact
# ids; inventing our own would make TLP markings unrecognizable downstream.

_TLP_EXTENSION_DEFINITION: dict[str, Any] = {
    "type": "extension-definition",
    "spec_version": "2.1",
    "id": "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d",
    "created": "2022-10-01T00:00:00.000Z",
    "modified": "2022-10-01T00:00:00.000Z",
    "name": "TLP 2.0",
    "description": "This defines TLP 2.0 as a STIX extension",
    "created_by_ref": "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
    "schema": (
        "https://github.com/oasis-open/cti-stix-common-objects/tree/master/"
        "extension-definition-specifications/tlp-2.0"
    ),
    "version": "1.0.0",
    "extension_types": ["property-extension"],
}


def _tlp_marking(name: str, marking_id: str, value: str) -> dict[str, Any]:
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2022-10-01T00:00:00.000Z",
        "name": name,
        "extensions": {
            _TLP_EXTENSION_DEFINITION["id"]: {
                "extension_type": "property-extension",
                "tlp_2_0": value,
            }
        },
    }


TLP_MARKINGS: dict[str, dict[str, Any]] = {
    "TLP:RED": _tlp_marking(
        "TLP:RED", "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1", "red"
    ),
    "TLP:AMBER+STRICT": _tlp_marking(
        "TLP:AMBER+STRICT",
        "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        "amber+strict",
    ),
    "TLP:AMBER": _tlp_marking(
        "TLP:AMBER", "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", "amber"
    ),
    "TLP:GREEN": _tlp_marking(
        "TLP:GREEN", "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb", "green"
    ),
    "TLP:CLEAR": _tlp_marking(
        "TLP:CLEAR", "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "clear"
    ),
}


class StixExportError(Exception):
    """Raised when a bundle cannot be built without violating a hard
    rule. Most importantly, never inventing a MITRE ATT&CK STIX id."""


def _stix_id(obj_type: str, *parts: str) -> str:
    """Deterministic STIX id: a UUIDv5 of stable content, not `uuid4()`."""
    name = ":".join(("ledgerhound", obj_type, *parts))
    return f"{obj_type}--{uuid.uuid5(uuid.NAMESPACE_URL, name)}"


def _indicator_pattern(indicator_type: str, value: str) -> str:
    """STIX has no native cryptocurrency-address or messaging-handle
    observable type, so chain addresses and Telegram handles use a
    documented custom SCO referenced by name in the pattern (`x-crypto-
    address`, `x-telegram-handle`). Legal per STIX 2.1's `x-`-prefixed
    custom-type naming rule. Domains and URLs use their real native SCOs.

    `x-crypto-address` schema: `value` (str, the address) and `chain`
    (str, one of btc/eth/tron/sol). `x-telegram-handle` schema: `value`
    (str, the handle including its leading `@`).
    """
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    if indicator_type == "domain":
        return f"[domain-name:value = '{escaped}']"
    if indicator_type == "url":
        return f"[url:value = '{escaped}']"
    if indicator_type in _CHAIN_INDICATOR_TYPES:
        chain = _CHAIN_BY_INDICATOR_TYPE[indicator_type]
        return f"[x-crypto-address:value = '{escaped}' AND x-crypto-address:chain = '{chain}']"
    if indicator_type == "telegram_handle":
        return f"[x-telegram-handle:value = '{escaped}']"
    raise StixExportError(f"No STIX pattern mapping for indicator type {indicator_type!r}")


def build_campaign_bundle(
    campaign: Campaign,
    assessment: Assessment,
    pack: EvidencePack,
    *,
    attack_dataset: AttackDataset,
    tlp: str = "TLP:CLEAR",
) -> dict[str, Any]:
    """Build a full STIX 2.1 bundle for one campaign's approved
    assessment. Pure function of its arguments, no DB session, no
    network, so the same inputs always produce the same bundle."""
    if tlp not in TLP_MARKINGS:
        raise StixExportError(f"Unknown TLP marking {tlp!r}. Valid: {sorted(TLP_MARKINGS)}")
    marking = TLP_MARKINGS[tlp]
    marking_refs = [marking["id"]]

    draft = assessment.draft
    analyst = assessment.reviewed_by or "unknown"
    as_of: datetime = assessment.reviewed_at or campaign.last_seen

    identity_id = _stix_id("identity", "ledgerhound", analyst)
    identity = stix2.v21.Identity(
        id=identity_id,
        created=as_of,
        modified=as_of,
        name="Ledgerhound",
        description=f"Crypto-scam campaign intelligence pipeline. Author: {PRODUCT_AUTHOR}.",
        identity_class="organization",
        contact_information=f"Author: {PRODUCT_AUTHOR}. Analyst: {analyst}",
    )

    campaign_id = _stix_id("campaign", campaign.code)
    campaign_obj = stix2.v21.Campaign(
        id=campaign_id,
        created=as_of,
        modified=as_of,
        created_by_ref=identity_id,
        name=campaign.display_name or campaign.code,
        description=draft["summary"],
        first_seen=campaign.first_seen,
        last_seen=campaign.last_seen,
        object_marking_refs=marking_refs,
    )

    objects: list[Any] = [identity, _TLP_EXTENSION_DEFINITION, marking, campaign_obj]
    object_refs: list[str] = [campaign_id]

    indicator_id_by_ref: dict[str, str] = {}
    for member in pack.members:
        indicator_id = _stix_id("indicator", campaign.code, member.indicator_type, member.value)
        indicator_id_by_ref[member.ref] = indicator_id
        objects.append(
            stix2.v21.Indicator(
                id=indicator_id,
                created=as_of,
                modified=as_of,
                created_by_ref=identity_id,
                name=member.value,
                description=f"{member.indicator_type} observed as part of campaign {campaign.code}",
                indicator_types=["malicious-activity"],
                pattern=_indicator_pattern(member.indicator_type, member.value),
                pattern_type="stix",
                # `EvidencePack` stores timestamps as ISO strings (so the
                # pack itself is plain JSON for hashing); stix2 only
                # reliably parses datetime objects or its own narrow
                # `...Z` string format, so parse back to a real datetime.
                valid_from=datetime.fromisoformat(member.first_seen),
                object_marking_refs=marking_refs,
            )
        )
        objects.append(
            stix2.v21.Relationship(
                id=_stix_id("relationship", indicator_id, campaign_id, "indicates"),
                created=as_of,
                modified=as_of,
                created_by_ref=identity_id,
                relationship_type="indicates",
                source_ref=indicator_id,
                target_ref=campaign_id,
                object_marking_refs=marking_refs,
            )
        )
        object_refs.append(indicator_id)

    for ttp in draft.get("ttps", []):
        technique_id = ttp["technique_id"]
        attack_pattern_id = attack_dataset.stix_id_for(technique_id)
        if attack_pattern_id is None:
            raise StixExportError(
                f"ATT&CK technique {technique_id!r} is not in the cached ATT&CK dataset; "
                "refusing to invent a STIX id for it. Refresh the cache (`lh assess draft` "
                "on any campaign) and try again."
            )
        objects.append(
            stix2.v21.AttackPattern(
                id=attack_pattern_id,
                created=as_of,
                modified=as_of,
                created_by_ref=identity_id,
                name=attack_dataset.name_for(technique_id) or ttp["technique_name"],
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": (
                            "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/")
                        ),
                    }
                ],
                object_marking_refs=marking_refs,
            )
        )
        objects.append(
            stix2.v21.Relationship(
                id=_stix_id("relationship", campaign_id, attack_pattern_id, "uses"),
                created=as_of,
                modified=as_of,
                created_by_ref=identity_id,
                relationship_type="uses",
                source_ref=campaign_id,
                target_ref=attack_pattern_id,
                object_marking_refs=marking_refs,
            )
        )
        object_refs.append(attack_pattern_id)

    report_id = _stix_id("report", campaign.code, str(assessment.version))
    report_obj = stix2.v21.Report(
        id=report_id,
        created=as_of,
        modified=as_of,
        created_by_ref=identity_id,
        name=f"{campaign.code}: {draft['summary'][:80]}",
        description=draft["assessment"],
        report_types=["campaign"],
        published=as_of,
        object_refs=sorted(set(object_refs), key=str),
        confidence=CONFIDENCE_SCALE[overall_confidence(draft)],
        object_marking_refs=marking_refs,
    )
    objects.append(report_obj)

    # Deterministic object order: sort by (type, id) so the same set of
    # objects always serializes identically regardless of construction
    # order above.
    def _sort_key(obj: Any) -> tuple[str, str]:
        as_dict = obj if isinstance(obj, dict) else json.loads(obj.serialize())
        return (as_dict["type"], as_dict["id"])

    objects.sort(key=_sort_key)

    bundle = stix2.v21.Bundle(
        id=_stix_id("bundle", campaign.code, str(assessment.version)),
        objects=objects,
        allow_custom=True,
    )
    result: dict[str, Any] = json.loads(bundle.serialize())
    return result


def serialize_bundle(bundle: dict[str, Any]) -> bytes:
    """Canonical, deterministic byte serialization of a bundle dict."""
    return (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8")

