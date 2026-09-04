"""Campaign entity graph and per-indicator explain — both built from
existing business logic: `assess.evidence.build_evidence_pack` for the
graph (it already has every member, edge, and label a campaign's graph
needs) and `cluster.graph.explain_indicator` for the explain endpoint,
never re-derived here."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.api.deps import get_session
from ledgerhound.api.routers.campaigns import get_campaign_or_404
from ledgerhound.api.schemas.graph import (
    CampaignGraph,
    DirectEdgeOut,
    ExplainOut,
    GraphEdge,
    GraphNode,
)
from ledgerhound.assess.evidence import build_evidence_pack
from ledgerhound.cluster.graph import explain_indicator
from ledgerhound.db.models import Indicator

router = APIRouter(prefix="/api/campaigns", tags=["graph"])


@router.get("/{code}/graph", response_model=CampaignGraph)
def get_campaign_graph(code: str, session: Session = Depends(get_session)) -> CampaignGraph:
    campaign = get_campaign_or_404(session, code)
    pack = build_evidence_pack(session, campaign)

    labels_by_member_ref: dict[str, list[dict[str, object]]] = {}
    for label in pack.labels:
        labels_by_member_ref.setdefault(label.member_ref, []).append(label.model_dump())

    nodes = [
        GraphNode(
            id=member.ref,
            type=member.indicator_type,
            value=member.value,
            labels=labels_by_member_ref.get(member.ref, []),
        )
        for member in pack.members
    ]
    edges = [
        GraphEdge(
            source=edge.src_ref,
            target=edge.dst_ref,
            relation=edge.relation,
            weight=edge.weight,
            evidence=edge.evidence,
        )
        for edge in pack.edges
    ]
    return CampaignGraph(nodes=nodes, edges=edges)


@router.get("/{code}/explain/{indicator_id}", response_model=ExplainOut)
def explain(code: str, indicator_id: str, session: Session = Depends(get_session)) -> ExplainOut:
    campaign = get_campaign_or_404(session, code)
    try:
        indicator_uuid = UUID(indicator_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid indicator id") from exc

    indicator = session.get(Indicator, indicator_uuid)
    if indicator is None:
        raise HTTPException(status_code=404, detail=f"No indicator with id {indicator_id!r}")

    result = explain_indicator(session, indicator_uuid, campaign.id)
    if indicator_uuid not in result.member_ids:
        raise HTTPException(
            status_code=404, detail=f"{indicator.value!r} is not a member of {code!r}"
        )

    indicators_by_id = {
        i.id: i
        for i in session.scalars(select(Indicator).where(Indicator.id.in_(result.member_ids)))
    }
    direct_edges_out = [
        DirectEdgeOut(
            neighbor_id=str(edge.neighbor_id),
            neighbor_value=(
                indicators_by_id[edge.neighbor_id].value
                if edge.neighbor_id in indicators_by_id
                else None
            ),
            relation=edge.relation,
            weight=edge.weight,
            evidence=edge.evidence,
        )
        for edge in result.direct_edges
    ]
    path_out = (
        [str(node_id) for node_id in result.path_to_reference] if result.path_to_reference else None
    )
    return ExplainOut(
        indicator_id=str(indicator.id),
        indicator_value=indicator.value,
        campaign_code=campaign.code,
        direct_edges=direct_edges_out,
        path_to_reference=path_out,
    )
