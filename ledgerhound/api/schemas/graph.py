"""Response models for the entity-graph and explain endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class GraphNode(BaseModel):
    id: str
    type: str
    value: str
    labels: list[dict[str, Any]]


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    weight: float
    evidence: dict[str, Any]


class CampaignGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class DirectEdgeOut(BaseModel):
    neighbor_id: str
    neighbor_value: str | None
    relation: str
    weight: float
    evidence: dict[str, Any]


class ExplainOut(BaseModel):
    indicator_id: str
    indicator_value: str
    campaign_code: str
    direct_edges: list[DirectEdgeOut]
    #: Indicator ids along the shortest path to the campaign's
    #: deterministic reference member; null if the indicator *is* the
    #: reference, has a direct edge already, or no path exists.
    path_to_reference: list[str] | None
