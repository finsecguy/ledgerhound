"""MITRE ATT&CK Enterprise technique dataset.

`drafter.py` rejects any assessment draft that cites a `technique_id` not
in this dataset, an assessment can't claim tradecraft that doesn't
exist in ATT&CK. The dataset is loaded from MITRE's public STIX bundle
once and cached locally as a small distilled `{technique_id: name}` map
(not the ~30MB raw bundle) so every later command is a fast local read,
not a re-fetch. ATT&CK releases only a handful of times a year, so
there's no TTL the way there is for OFAC's daily SDN list: the cache is
refreshed only when missing or when the caller explicitly asks for it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

ATTACK_ENTERPRISE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


@dataclass(frozen=True, slots=True)
class AttackDataset:
    """A distilled technique_id -> name map, the collection version it
    was built from (recorded so an assessment can note which ATT&CK
    release its `ttps` were validated against), and technique_id -> the
    technique's real MITRE STIX id (`attack-pattern--<uuid>`). Milestone
    5's STIX export must reference MITRE's own canonical object ids and
    is forbidden from inventing new ones."""

    version: str
    techniques: dict[str, str]
    stix_ids: dict[str, str] = field(default_factory=dict)

    def is_valid_id(self, technique_id: str) -> bool:
        return technique_id in self.techniques

    def name_for(self, technique_id: str) -> str | None:
        return self.techniques.get(technique_id)

    def stix_id_for(self, technique_id: str) -> str | None:
        return self.stix_ids.get(technique_id)


def parse_stix_bundle(raw: dict[str, Any]) -> AttackDataset:
    """Extract non-revoked, non-deprecated technique ids/names/STIX ids
    and the collection version from a raw ATT&CK Enterprise STIX bundle."""
    version = "unknown"
    techniques: dict[str, str] = {}
    stix_ids: dict[str, str] = {}
    for obj in raw.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "x-mitre-collection":
            # MITRE's field is `x_mitre_version` (e.g. "19.2"), not the
            # generic STIX `version`. Confirmed against the live bundle;
            # every ATT&CK-specific field in this schema is `x_mitre_*`.
            version = obj.get("x_mitre_version") or version
            continue
        if obj_type != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = next(
            (
                ref.get("external_id")
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            ),
            None,
        )
        if technique_id is None:
            continue
        techniques[technique_id] = obj.get("name", "")
        stix_id = obj.get("id")
        if stix_id:
            stix_ids[technique_id] = stix_id
    return AttackDataset(version=version, techniques=techniques, stix_ids=stix_ids)


def _read_cache(cache_path: Path) -> AttackDataset | None:
    if not cache_path.is_file():
        return None
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    return AttackDataset(
        version=payload["version"],
        techniques=payload["techniques"],
        stix_ids=payload.get("stix_ids", {}),
    )


def _write_cache(cache_path: Path, dataset: AttackDataset) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "version": dataset.version,
                "techniques": dataset.techniques,
                "stix_ids": dataset.stix_ids,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def load_attack_dataset(
    cache_path: Path,
    *,
    client: httpx.Client | None = None,
    force_refresh: bool = False,
) -> AttackDataset:
    """Load the distilled dataset from the local cache, refreshing from
    MITRE's public STIX bundle only if the cache is missing or
    `force_refresh` is set. `client` is injectable so tests never hit the
    real network."""
    if not force_refresh:
        cached = _read_cache(cache_path)
        if cached is not None:
            return cached

    owns_client = client is None
    http_client = client if client is not None else httpx.Client(timeout=60.0)
    try:
        response = http_client.get(ATTACK_ENTERPRISE_STIX_URL)
        response.raise_for_status()
        dataset = parse_stix_bundle(response.json())
    finally:
        if owns_client:
            http_client.close()

    _write_cache(cache_path, dataset)
    logger.info(
        "attack_dataset_refreshed", version=dataset.version, technique_count=len(dataset.techniques)
    )
    return dataset


class AttackDatasetUnavailableError(Exception):
    """Raised by `load_cached_attack_dataset` when no local cache exists."""


def load_cached_attack_dataset(cache_path: Path) -> AttackDataset:
    """Load the distilled dataset from the local cache only. Never
    fetches. Used by `ledgerhound.export`, which is forbidden from making
    network calls: STIX export needs MITRE's real technique STIX ids, but
    must get them from whatever `lh assess draft` already cached, not a
    fresh fetch of its own."""
    cached = _read_cache(cache_path)
    if cached is None:
        raise AttackDatasetUnavailableError(
            f"No cached ATT&CK dataset at {cache_path}. Run `lh assess draft` on any "
            "campaign at least once to populate it before exporting."
        )
    return cached

