"""Collector for ScamSniffer's public Web3 blocklists.

ScamSniffer maintains a community-curated, daily-updated blocklist of
malicious domains and addresses in their `scam-database` GitHub repo,
published as plain JSON arrays of strings:

- https://github.com/scamsniffer/scam-database/blob/main/blacklist/domains.json
- https://github.com/scamsniffer/scam-database/blob/main/blacklist/address.json

Each entry in either list becomes one raw record.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import httpx

from ledgerhound.collect.base import Collector, fetch_url

DOMAINS_URL = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json"
ADDRESS_URL = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"


class ScamSnifferCollector(Collector):
    name = "scamsniffer"

    def fetch(self) -> Iterable[dict[str, Any]]:
        with self._build_client() as client:
            yield from self._fetch_list(client, DOMAINS_URL, "domains")
            yield from self._fetch_list(client, ADDRESS_URL, "address")

    def _fetch_list(
        self, client: httpx.Client, url: str, list_name: str
    ) -> Iterable[dict[str, Any]]:
        try:
            response = fetch_url(client, url, settings=self.settings)
            entries = response.json()
        except httpx.HTTPError as exc:
            self.log.error("scamsniffer_fetch_failed", url=url, error=str(exc))
            return
        except ValueError as exc:
            self.log.error("scamsniffer_invalid_json", url=url, error=str(exc))
            return

        if not isinstance(entries, list):
            self.log.error("scamsniffer_unexpected_shape", url=url, type=type(entries).__name__)
            return

        for entry in entries:
            try:
                if not isinstance(entry, str) or not entry.strip():
                    raise ValueError(f"expected a non-empty string entry, got {entry!r}")
                yield {"list": list_name, "value": entry.strip()}
            except Exception:
                self.log.warning("scamsniffer_malformed_entry", list=list_name, entry=entry)
                continue

    def content_hash(self, record: dict[str, Any]) -> str:
        return self.stable_hash({"list": record["list"], "value": record["value"]})
