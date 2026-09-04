"""Relation registry: every detector `lh cluster run` knows about."""

from __future__ import annotations

from ledgerhound.cluster.relations.base import EdgeCandidate, LabelIndex, Relation, load_label_index
from ledgerhound.cluster.relations.cashout import SharesCashoutPathRelation
from ledgerhound.cluster.relations.cert import SharesCertRelation
from ledgerhound.cluster.relations.registrar_ns import SharesRegistrarAndNsRelation
from ledgerhound.cluster.relations.template import SharesTemplateRelation
from ledgerhound.cluster.relations.wallet import SharesReceivingWalletRelation

#: Order matters only for readability of `lh cluster run` output — edge
#: sync/graph-building/scoring are all order-independent by construction.
ALL_RELATIONS: dict[str, type[Relation]] = {
    relation_cls.name: relation_cls
    for relation_cls in (
        SharesReceivingWalletRelation,
        SharesCashoutPathRelation,
        SharesCertRelation,
        SharesRegistrarAndNsRelation,
        SharesTemplateRelation,
    )
}

__all__ = [
    "ALL_RELATIONS",
    "EdgeCandidate",
    "LabelIndex",
    "Relation",
    "load_label_index",
]
