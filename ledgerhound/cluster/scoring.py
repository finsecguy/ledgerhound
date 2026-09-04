"""Campaign confidence scoring.

score = (sum of edge weights in the component / node count) + a
diversity bonus when more than one relation type corroborates the
component. A component whose *only* relation is `shares_registrar_and_ns`
scores exactly 0 — enforced here, explicitly, not left to the weight
being low enough to usually fall under the threshold.
"""

from __future__ import annotations

from collections.abc import Collection
from uuid import UUID

import networkx as nx

from ledgerhound.cluster.config import CampaignConfig

#: This relation is corroboration-only. A component linked by nothing
#: else can never become a campaign, regardless of edge count or weight.
_CORROBORATION_ONLY_RELATIONS = {"shares_registrar_and_ns"}


def component_relation_types(graph: nx.Graph, component: Collection[UUID]) -> set[str]:
    types: set[str] = set()
    nodes = set(component)
    for u, v, data in graph.edges(nodes, data=True):
        if u in nodes and v in nodes:
            for contribution in data["relations"]:
                types.add(contribution["relation"])
    return types


def component_weight_sum(graph: nx.Graph, component: Collection[UUID]) -> float:
    total = 0.0
    nodes = set(component)
    for u, v, data in graph.edges(nodes, data=True):
        if u in nodes and v in nodes:
            total += sum(contribution["weight"] for contribution in data["relations"])
    return total


def score_component(
    graph: nx.Graph, component: Collection[UUID], config: CampaignConfig
) -> tuple[float, set[str]]:
    """Returns (score, relation_types). `relation_types` is returned
    alongside the score because callers persist it as evidence on the
    `Campaign` row — it's the answer to "why does this cluster exist."
    """
    relation_types = component_relation_types(graph, component)

    if relation_types and relation_types <= _CORROBORATION_ONLY_RELATIONS:
        return 0.0, relation_types

    node_count = len(set(component))
    if node_count == 0:
        return 0.0, relation_types

    score = component_weight_sum(graph, component) / node_count
    if len(relation_types) > 1:
        score += config.diversity_bonus
    return score, relation_types
