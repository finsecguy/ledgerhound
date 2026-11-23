"""Known-address label sets: mixers, bridges, exchange deposit addresses.

Backed by `data/known_addresses.yaml`, a versioned, hand-curated file
where every non-empty set carries its source and retrieval date. See that
file for what's actually populated today and why some sets ship empty
(no free, verifiable bulk dataset existed at authoring time for that
category. See the README's "Known Limitations" section).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, model_validator

from ledgerhound.enrich.base import AddressLabelHit, Chain, LabelType

DEFAULT_DATA_PATH = Path(__file__).parent / "data" / "known_addresses.yaml"


class KnownAddressSet(BaseModel):
    chain: Chain
    label_type: LabelType
    label: str | None = None
    source: str | None = None
    #: Public page that names these addresses. Required whenever
    #: `addresses` is non-empty, so a label cannot ship without a citation.
    source_url: str | None = None
    retrieved_at: date | None = None
    confidence: float | None = None
    notes: str = ""
    addresses: list[str] = []

    @model_validator(mode="after")
    def _cited_when_populated(self) -> Self:
        if self.addresses and (not self.source or not self.source_url):
            raise ValueError(
                "a non-empty known-address set needs both source and source_url"
            )
        return self


class KnownAddressesFile(BaseModel):
    version: int
    sets: list[KnownAddressSet]


def _normalize(chain: Chain, address: str) -> str:
    return address.lower() if chain == "eth" else address


class KnownAddressIndex:
    """In-memory (chain, address) -> AddressLabelHit lookup."""

    def __init__(self, sets: list[KnownAddressSet]) -> None:
        self._by_key: dict[tuple[Chain, str], AddressLabelHit] = {}
        self._counts: dict[str, int] = {}
        for address_set in sets:
            self._counts[address_set.label_type] = self._counts.get(
                address_set.label_type, 0
            ) + len(address_set.addresses)
            if not address_set.addresses:
                continue
            source = address_set.source or "unknown"
            if address_set.source_url and address_set.source_url not in source:
                source = f"{source} ({address_set.source_url})"
            hit = AddressLabelHit(
                label=address_set.label or address_set.label_type,
                label_type=address_set.label_type,
                source=source,
                confidence=address_set.confidence if address_set.confidence is not None else 0.5,
            )
            for address in address_set.addresses:
                self._by_key[(address_set.chain, _normalize(address_set.chain, address))] = hit

    def lookup(self, chain: Chain, address: str) -> AddressLabelHit | None:
        return self._by_key.get((chain, _normalize(chain, address)))

    def count_by_label_type(self) -> dict[str, int]:
        return dict(self._counts)

    def __len__(self) -> int:
        return len(self._by_key)

    @classmethod
    def load(cls, path: Path = DEFAULT_DATA_PATH) -> KnownAddressIndex:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        parsed = KnownAddressesFile.model_validate(raw)
        return cls(parsed.sets)

