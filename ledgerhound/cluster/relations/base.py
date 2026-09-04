"""Relation detector abstraction.

A `Relation` reads projection tables (never the network — clustering
must be deterministic, per the milestone's constraints) and emits
`EdgeCandidate`s. Evidence is a structured dict specific to the relation
and must be sufficient to reproduce the finding by hand, since a report
will print it verbatim.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from ledgerhound.cluster.config import ClusteringConfig
from ledgerhound.enrich.base import Chain
from ledgerhound.enrich.labels.known import KnownAddressIndex
from ledgerhound.enrich.labels.ofac import OFACList


@dataclass(frozen=True, slots=True)
class EdgeCandidate:
    src_indicator_id: UUID
    dst_indicator_id: UUID
    relation: str
    weight: float
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LabelIndex:
    """A synchronous, no-network union of OFAC + known-address labels,
    for the "exchange/mixer addresses can't act as a linking node" rule.

    Loaded from whatever's already on disk (the OFAC cache file written
    by `lh enrich`, the bundled known-addresses dataset) — clustering
    never makes a network call, so a missing/stale cache just means this
    exclusion check sees less data, not a failure.
    """

    ofac: OFACList | None
    known: KnownAddressIndex | None

    def label_type(self, chain: Chain, address: str) -> str | None:
        if self.ofac is not None:
            hit = self.ofac.lookup(chain, address)
            if hit is not None:
                return "sanctioned"
        if self.known is not None:
            known_hit = self.known.lookup(chain, address)
            if known_hit is not None:
                return known_hit.label_type
        return None

    def is_excluded_linking_node(self, chain: Chain, address: str) -> bool:
        """Exchange/mixer addresses are excluded from acting as a linking
        node between two indicators — two unrelated scams both cashing
        out at the same exchange deposit cluster are not the same
        campaign. Bridges and sanctioned addresses are NOT excluded here
        (only `shares_cashout_path` deals with those, as evidence only,
        never as a graph node)."""
        return self.label_type(chain, address) in ("exchange", "mixer")


def load_label_index(
    *, ofac_cache_path: Path, known_addresses_path: Path | None = None
) -> LabelIndex:
    ofac: OFACList | None = None
    if ofac_cache_path.is_file():
        try:
            ofac = OFACList.parse(ofac_cache_path.read_bytes())
        except Exception:  # noqa: BLE001 - a corrupt/stale cache degrades, doesn't crash
            ofac = None
    known = (
        KnownAddressIndex.load(known_addresses_path)
        if known_addresses_path
        else KnownAddressIndex.load()
    )
    return LabelIndex(ofac=ofac, known=known)


def sorted_pairs(indicator_ids: Iterable[UUID]) -> list[tuple[UUID, UUID]]:
    """Every distinct pair from a group of indicator ids that share some
    evidence, in a stable order — sorted by string form, since UUIDs
    don't have a meaningful numeric ordering but need *some* fixed one
    for determinism across runs."""
    distinct = sorted(set(indicator_ids), key=str)
    return list(combinations(distinct, 2))


class Relation(ABC):
    """Base class for every relation detector."""

    name: str
    base_weight: float

    def __init__(self, config: ClusteringConfig, *, label_index: LabelIndex | None = None) -> None:
        self.config = config
        self.label_index = label_index

    @abstractmethod
    def detect(self, session: Session) -> Iterable[EdgeCandidate]:
        """Read projection tables and emit candidate edges.

        Must be side-effect free (no writes, no network) and must
        iterate its inputs in a deterministic (sorted) order — clustering
        as a whole must produce byte-identical output for the same
        database state on every run.
        """
        raise NotImplementedError
