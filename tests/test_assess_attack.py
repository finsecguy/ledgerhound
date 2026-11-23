"""ATT&CK STIX bundle parsing (revoked/deprecated exclusion) and the
local-cache-first loading behavior, a second load must never touch the
network once the cache exists."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from ledgerhound.assess.attack import (
    AttackDatasetUnavailableError,
    load_attack_dataset,
    load_cached_attack_dataset,
    parse_stix_bundle,
)

FIXTURE_BUNDLE: dict[str, Any] = {
    "type": "bundle",
    "objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "15.1"},
        {
            "type": "attack-pattern",
            "id": "attack-pattern--3d2f0a6c-6d1c-4d6f-8b1e-1a2b3c4d5e6f",
            "name": "Phishing",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}],
        },
        {
            "type": "attack-pattern",
            "name": "Spearphishing Attachment",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}],
        },
        {
            "type": "attack-pattern",
            "name": "Deprecated Thing",
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Thing",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T8888"}],
        },
    ],
}


def test_parse_stix_bundle_excludes_revoked_and_deprecated() -> None:
    dataset = parse_stix_bundle(FIXTURE_BUNDLE)

    assert dataset.version == "15.1"
    assert dataset.is_valid_id("T1566")
    assert dataset.is_valid_id("T1566.001")
    assert not dataset.is_valid_id("T9999")
    assert not dataset.is_valid_id("T8888")
    assert dataset.name_for("T1566") == "Phishing"
    assert dataset.stix_id_for("T1566") == "attack-pattern--3d2f0a6c-6d1c-4d6f-8b1e-1a2b3c4d5e6f"
    assert dataset.stix_id_for("T9999") is None


def test_load_attack_dataset_fetches_once_then_serves_from_cache(tmp_path: Path) -> None:
    cache_path = tmp_path / "attack.json"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=FIXTURE_BUNDLE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    dataset = load_attack_dataset(cache_path, client=client)
    assert dataset.is_valid_id("T1566")
    assert cache_path.is_file()
    assert json.loads(cache_path.read_text())["version"] == "15.1"

    def failing_handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("network should not be hit once the cache exists")

    cached_client = httpx.Client(transport=httpx.MockTransport(failing_handler))
    dataset_from_cache = load_attack_dataset(cache_path, client=cached_client)
    assert dataset_from_cache.is_valid_id("T1566")

    offline = load_cached_attack_dataset(cache_path)
    assert offline.stix_id_for("T1566") == "attack-pattern--3d2f0a6c-6d1c-4d6f-8b1e-1a2b3c4d5e6f"


def test_load_cached_attack_dataset_raises_when_no_cache_exists(tmp_path: Path) -> None:
    with pytest.raises(AttackDatasetUnavailableError):
        load_cached_attack_dataset(tmp_path / "missing.json")

