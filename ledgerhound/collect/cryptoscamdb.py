"""Collector for the CryptoScamDB public scam dataset.

CryptoScamDB (the project that continued EtherScamDB) publishes a
community database of reported cryptocurrency scams. The v1 HTTP API is
documented by the open-source server at
https://github.com/CryptoScamDB/api.cryptoscamdb.org and is a single GET:

    GET https://api.cryptoscamdb.org/v1/scams

The body is ``{"success": true, "result": [ ...entries ]}``. Each entry
is one raw record. `addresses` is either a list of strings or an object
whose values are strings or lists of strings (coin symbol to addresses).
Both shapes are flattened to a list of strings before the record is
stored. A malformed entry is logged and skipped.

Terms, the MIT licence on the API server, and the rate-limit posture are
recorded in ``docs/data-sources.md``. This collector issues one GET per
run. It does not poll per indicator.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import httpx

from ledgerhound.collect.base import Collector, fetch_url

FEED_URL = "https://api.cryptoscamdb.org/v1/scams"


def _flatten_addresses(raw: Any) -> list[str]:
    found: list[str] = []
    if isinstance(raw, str):
        if raw.strip():
            found.append(raw.strip())
        return found
    if isinstance(raw, list):
        for item in raw:
            found.extend(_flatten_addresses(item))
        return found
    if isinstance(raw, dict):
        for value in raw.values():
            found.extend(_flatten_addresses(value))
    return found


def _optional_str(entry: dict[str, Any], key: str) -> str | None:
    value = entry.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def normalize_entry(entry: Any) -> dict[str, Any] | None:
    """Return a stable record, or None when the entry has nothing usable."""
    if not isinstance(entry, dict):
        return None
    url = _optional_str(entry, "url")
    addresses = _flatten_addresses(entry.get("addresses"))
    if url is None and not addresses:
        return None
    identifier = entry.get("id")
    if not isinstance(identifier, int | str):
        identifier = None
    return {
        "id": identifier,
        "name": _optional_str(entry, "name"),
        "url": url,
        "category": _optional_str(entry, "category"),
        "subcategory": _optional_str(entry, "subcategory"),
        "description": _optional_str(entry, "description"),
        "addresses": addresses,
        "reporter": _optional_str(entry, "reporter"),
        "status": _optional_str(entry, "status"),
    }


class CryptoScamDBCollector(Collector):
    name = "cryptoscamdb"

    def fetch(self) -> Iterable[dict[str, Any]]:
        with self._build_client() as client:
            try:
                response = fetch_url(client, FEED_URL, settings=self.settings)
                payload = response.json()
            except httpx.HTTPError as exc:
                self.log.error("cryptoscamdb_fetch_failed", error=str(exc))
                return
            except ValueError as exc:
                self.log.error("cryptoscamdb_invalid_json", error=str(exc))
                return

        if not isinstance(payload, dict) or not isinstance(payload.get("result"), list):
            self.log.error("cryptoscamdb_unexpected_shape", type=type(payload).__name__)
            return
        if payload.get("success") is False:
            self.log.error("cryptoscamdb_success_false")
            return

        for entry in payload["result"]:
            try:
                record = normalize_entry(entry)
                if record is None:
                    raise ValueError("entry has no url and no addresses")
            except Exception:
                self.log.warning("cryptoscamdb_malformed_entry", entry=entry)
                continue
            yield record

    def content_hash(self, record: dict[str, Any]) -> str:
        return self.stable_hash(record)
