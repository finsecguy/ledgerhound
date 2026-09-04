"""Builds a networkx graph from the persisted `edges` table.

Multiple relations between the same pair of indicators (e.g. they share
both a receiving wallet and a registrar/NS set) become multiple entries
in that single graph edge's `relations` attribute, not parallel graph
edges — connectivity is what defines a component; which specific
relation(s) carried it is scoring/evidence data, read off the edge
attribute by `cluster.scoring`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.db.models import CampaignMember, Edge


def build_graph(session: Session) -> nx.Graph:
    graph: nx.Graph = nx.Graph()
    rows = session.execute(
        select(
            Edge.src_indicator_id, Edge.dst_indicator_id, Edge.relation, Edge.weight, Edge.evidence
        )
    ).all()

    # Sorted for determinism: insertion order into a networkx graph can
    # affect internal dict ordering, and this whole pipeline promises
    # byte-identical output for the same database state on every run.
    for src, dst, relation, weight, evidence in sorted(
        rows, key=lambda r: (str(r[0]), str(r[1]), str(r[2]))
    ):
        relation_value = relation.value if hasattr(relation, "value") else str(relation)
        graph.add_node(src)
        graph.add_node(dst)
        contribution = {"relation": relation_value, "weight": weight, "evidence": evidence}
        if graph.has_edge(src, dst):
            graph[src][dst]["relations"].append(contribution)
        else:
            graph.add_edge(src, dst, relations=[contribution])

    return graph


@dataclass(frozen=True, slots=True)
class DirectEdge:
    neighbor_id: UUID
    relation: str
    weight: float
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ExplainResult:
    """Why one indicator belongs to its campaign: its direct edges plus
    a path to the campaign's deterministic reference member (lowest-id,
    for context on larger campaigns) — the answer `lh cluster explain`
    and the dashboard's explain endpoint both need, computed once here
    so they can never disagree."""

    campaign_id: UUID
    member_ids: frozenset[UUID]
    direct_edges: list[DirectEdge]
    reference_id: UUID
    #: None when the indicator *is* the reference member, or no path
    #: exists, or the path is trivial (a direct edge already covers it).
    path_to_reference: list[UUID] | None


def explain_indicator(session: Session, indicator_id: UUID, campaign_id: UUID) -> ExplainResult:
    member_ids = frozenset(
        m.indicator_id
        for m in session.scalars(
            select(CampaignMember).where(CampaignMember.campaign_id == campaign_id)
        )
    )
    edges = list(
        session.scalars(
            select(Edge).where(
                Edge.src_indicator_id.in_(member_ids), Edge.dst_indicator_id.in_(member_ids)
            )
        )
    )

    graph: nx.Graph = nx.Graph()
    graph.add_nodes_from(member_ids)
    for edge in edges:
        graph.add_edge(
            edge.src_indicator_id,
            edge.dst_indicator_id,
            relation=edge.relation.value,
            weight=edge.weight,
            evidence=edge.evidence,
        )

    direct_edges = (
        [
            DirectEdge(
                neighbor_id=neighbor_id,
                relation=graph[indicator_id][neighbor_id]["relation"],
                weight=graph[indicator_id][neighbor_id]["weight"],
                evidence=graph[indicator_id][neighbor_id]["evidence"],
            )
            for neighbor_id in sorted(graph.neighbors(indicator_id), key=str)
        ]
        if indicator_id in graph
        else []
    )

    reference_id = sorted(member_ids, key=str)[0]
    path_to_reference: list[UUID] | None = None
    if (
        reference_id != indicator_id
        and indicator_id in graph
        and nx.has_path(graph, indicator_id, reference_id)
    ):
        path = nx.shortest_path(graph, indicator_id, reference_id)
        if len(path) > 2:
            path_to_reference = path

    return ExplainResult(
        campaign_id=campaign_id,
        member_ids=member_ids,
        direct_edges=direct_edges,
        reference_id=reference_id,
        path_to_reference=path_to_reference,
    )
