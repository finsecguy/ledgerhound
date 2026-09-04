"""Collector for abuse.ch URLhaus recent-URLs CSV feed.

The feed is CSV wrapped in a `#`-prefixed comment header block (terms of
use, last-updated timestamp, and the actual column header line). We parse
the header line out of that comment block to get field names, then hand
the data rows to `csv.reader` — never naive string splitting, since URL
and tag fields can themselves contain commas inside quotes.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from typing import Any

import httpx

from ledgerhound.collect.base import Collector, fetch_url

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

#: Used only if the upstream comment block doesn't contain a recognizable
#: header line (defense in depth against a feed format change).
FALLBACK_FIELDNAMES = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
]


class URLhausCollector(Collector):
    name = "urlhaus"

    def fetch(self) -> Iterable[dict[str, Any]]:
        with self._build_client() as client:
            try:
                response = fetch_url(client, FEED_URL, settings=self.settings)
            except httpx.HTTPError as exc:
                self.log.error("urlhaus_fetch_failed", error=str(exc))
                return
        yield from self._parse_csv(response.text)

    def _parse_csv(self, text: str) -> Iterable[dict[str, Any]]:
        fieldnames: list[str] | None = None
        data_lines: list[str] = []

        for line in text.splitlines():
            if line.startswith("#"):
                candidate = line.lstrip("#").strip()
                first_field = candidate.split(",", 1)[0].strip().lower()
                if first_field == "id":
                    fieldnames = [name.strip() for name in candidate.split(",")]
                continue
            if line.strip():
                data_lines.append(line)

        if fieldnames is None:
            self.log.warning("urlhaus_header_not_found_using_fallback")
            fieldnames = FALLBACK_FIELDNAMES

        for row in csv.reader(data_lines):
            try:
                if len(row) != len(fieldnames):
                    raise ValueError(
                        f"expected {len(fieldnames)} columns, got {len(row)}: {row!r}"
                    )
                yield dict(zip(fieldnames, row, strict=True))
            except Exception:
                self.log.warning("urlhaus_malformed_row", row=row)
                continue

    def content_hash(self, record: dict[str, Any]) -> str:
        return self.stable_hash(record)
