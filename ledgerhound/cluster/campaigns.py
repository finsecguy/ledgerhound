"""Connected components -> campaigns, with stable identity across runs.

**Stable identity**: a campaign's `code` is assigned once and never
changes. On each run, newly computed qualifying components are matched
against existing campaigns' current member sets by Jaccard overlap
(`campaign.merge_split_jaccard_threshold`, default 0.5, mutual best
match). A new component matching exactly one existing campaign is a
continuation (same id, members updated). A new component that two or
more existing campaigns both best-match is a **merge** (the highest-
overlap existing campaign survives; the others are absorbed and lose
their members, but their row and code remain for historical reference).
An existing campaign whose best match splits across two or more new
components is a **split** (the highest-overlap component keeps the id;
the rest become brand-new campaigns). Every merge/split writes exactly
one `CampaignEvent` row with the exact before/after member sets.

Everything here is deterministic: candidate lists, component lists, and
member lists are all sorted before being iterated or compared, and ties
in Jaccard matching break on campaign code / component's lowest member
id — the same database state produces the same campaigns and the same
ids on every run.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import networkx as nx
import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ledgerhound.cluster.config import ClusteringConfig
from ledgerhound.cluster.graph import build_graph
from ledgerhound.cluster.relations import ALL_RELATIONS, EdgeCandidate, LabelIndex
from ledgerhound.cluster.scoring import score_component
from ledgerhound.db.models import (
    Campaign,
    CampaignEvent,
    CampaignMember,
    Edge,
    EdgeRelation,
    Indicator,
)

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ClusterRunResult:
    relations_run: list[str]
    edges_added: int
    edges_updated: int
    edges_removed: int
    components_considered: int
    campaigns_created: int
    campaigns_updated: int
    campaigns_merged: int
    campaigns_split: int
    dry_run: bool


def _sync_edges_for_relation(
    session: Session, relation_name: str, candidates: list[EdgeCandidate]
) -> tuple[int, int, int]:
    """Full sync, not just insert: an edge this relation no longer
    detects (because the underlying data changed) is removed, so the
    graph always reflects current database state, never stale history."""
    relation_enum = EdgeRelation(relation_name)
    existing = {
        (row.src_indicator_id, row.dst_indicator_id): row
        for row in session.scalars(select(Edge).where(Edge.relation == relation_enum))
    }

    new_keys: set[tuple[UUID, UUID]] = set()
    added = updated = 0
    for candidate in candidates:
        key = (candidate.src_indicator_id, candidate.dst_indicator_id)
        new_keys.add(key)
        existing_row = existing.get(key)
        if existing_row is None:
            session.add(
                Edge(
                    src_indicator_id=candidate.src_indicator_id,
                    dst_indicator_id=candidate.dst_indicator_id,
                    relation=relation_enum,
                    weight=candidate.weight,
                    evidence=candidate.evidence,
                )
            )
            added += 1
        elif existing_row.weight != candidate.weight or existing_row.evidence != candidate.evidence:
            existing_row.weight = candidate.weight
            existing_row.evidence = candidate.evidence
            updated += 1

    removed_keys = set(existing) - new_keys
    for key in removed_keys:
        session.delete(existing[key])
    session.flush()
    return added, updated, len(removed_keys)


def _jaccard(a: frozenset[UUID], b: frozenset[UUID]) -> float:
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _next_campaign_code(session: Session, year: int) -> str:
    prefix = f"LH-{year}-"
    max_n = 0
    for code in session.scalars(select(Campaign.code).where(Campaign.code.like(f"{prefix}%"))):
        try:
            max_n = max(max_n, int(code.rsplit("-", 1)[-1]))
        except ValueError:
            continue
    return f"{prefix}{max_n + 1:03d}"


def _create_campaign(
    session: Session,
    component: frozenset[UUID],
    score: float,
    relation_types: set[str],
    now: datetime,
) -> Campaign:
    campaign = Campaign(
        code=_next_campaign_code(session, now.year),
        status="active",
        score=score,
        relation_types=sorted(relation_types),
        first_seen=now,
        last_seen=now,
    )
    session.add(campaign)
    session.flush()
    for indicator_id in sorted(component, key=str):
        session.add(
            CampaignMember(campaign_id=campaign.id, indicator_id=indicator_id, joined_at=now)
        )
    # This session runs with autoflush=False (see db/session.py) — without
    # an explicit flush here, these CampaignMember rows stay invisible to
    # any query issued later in the same run (e.g.
    # _refresh_campaign_statuses' membership lookup), which would then
    # see zero members for a freshly-created campaign and wrongly mark it
    # dormant. Found via exactly that symptom during manual testing.
    session.flush()
    return campaign


def _set_campaign_members(
    session: Session, campaign_id: UUID, component: frozenset[UUID], now: datetime
) -> None:
    existing = {
        row.indicator_id: row
        for row in session.scalars(
            select(CampaignMember).where(CampaignMember.campaign_id == campaign_id)
        )
    }
    for indicator_id in sorted(component, key=str):
        if indicator_id not in existing:
            session.add(
                CampaignMember(campaign_id=campaign_id, indicator_id=indicator_id, joined_at=now)
            )
    for indicator_id, row in existing.items():
        if indicator_id not in component:
            session.delete(row)
    session.flush()  # see the comment in _create_campaign: autoflush=False


def _refresh_campaign_statuses(session: Session, config: ClusteringConfig) -> None:
    cutoff = datetime.now(UTC) - timedelta(days=config.campaign.active_window_days)
    for campaign in session.scalars(select(Campaign)):
        member_ids = list(
            session.scalars(
                select(CampaignMember.indicator_id).where(CampaignMember.campaign_id == campaign.id)
            )
        )
        if not member_ids:
            campaign.status = "dormant"
            continue
        recent = session.scalar(
            select(func.count(Indicator.id)).where(
                Indicator.id.in_(member_ids), Indicator.last_seen >= cutoff
            )
        )
        campaign.status = "active" if recent else "dormant"


@dataclass(slots=True)
class _CampaignCounts:
    created: int = 0
    updated: int = 0
    merged: int = 0
    split: int = 0


def _match_and_persist_campaigns(
    session: Session,
    qualifying: list[tuple[frozenset[UUID], float, set[str]]],
    config: ClusteringConfig,
    *,
    dry_run: bool,
) -> _CampaignCounts:
    counts = _CampaignCounts()
    now = datetime.now(UTC)
    threshold = config.campaign.merge_split_jaccard_threshold

    existing_campaigns = list(session.scalars(select(Campaign)))
    existing_by_id = {c.id: c for c in existing_campaigns}
    existing_members: dict[UUID, frozenset[UUID]] = {
        campaign.id: frozenset(
            session.scalars(
                select(CampaignMember.indicator_id).where(CampaignMember.campaign_id == campaign.id)
            )
        )
        for campaign in existing_campaigns
    }

    # Mutual-best-match, both directions. Inclusive (>=), not strict: two
    # equal-sized campaigns merging fully (e.g. {A,B} and {C,D} both
    # becoming {A,B,C,D}) lands exactly on Jaccard 0.5 with the default
    # threshold — that's the single most natural merge case there is, so
    # the boundary has to count, the same reasoning as the campaign score
    # threshold above.
    new_best: dict[int, tuple[float, UUID] | None] = {}
    for idx, (component, _score, _rel) in enumerate(qualifying):
        best: tuple[float, UUID] | None = None
        for camp_id, members in sorted(
            existing_members.items(), key=lambda kv: existing_by_id[kv[0]].code
        ):
            j = _jaccard(component, members)
            if j >= threshold and (best is None or j > best[0]):
                best = (j, camp_id)
        new_best[idx] = best

    existing_best: dict[UUID, tuple[float, int] | None] = {}
    for camp_id, members in existing_members.items():
        best_e: tuple[float, int] | None = None
        for idx, (component, _score, _rel) in enumerate(qualifying):
            j = _jaccard(component, members)
            if j >= threshold and (best_e is None or j > best_e[0]):
                best_e = (j, idx)
        existing_best[camp_id] = best_e

    handled_existing: set[UUID] = set()
    handled_new: set[int] = set()

    # --- Merges: a new component that 2+ existing campaigns best-match.
    new_idx_to_existing: dict[int, list[tuple[float, UUID]]] = defaultdict(list)
    for camp_id, best_e in existing_best.items():
        if best_e is not None:
            new_idx_to_existing[best_e[1]].append((best_e[0], camp_id))

    for new_idx, merge_matches in sorted(new_idx_to_existing.items()):
        if len(merge_matches) < 2:
            continue
        ranked = sorted(merge_matches, key=lambda m: (-m[0], existing_by_id[m[1]].code))
        survivor_id = ranked[0][1]
        absorbed_ids = [m[1] for m in ranked[1:]]
        component, score, relation_types = qualifying[new_idx]
        members_before = sorted(str(i) for i in existing_members[survivor_id])
        members_after = sorted(str(i) for i in component)

        if not dry_run:
            survivor = existing_by_id[survivor_id]
            _set_campaign_members(session, survivor_id, component, now)
            survivor.score = score
            survivor.relation_types = sorted(relation_types)
            survivor.last_seen = now
            for absorbed_id in absorbed_ids:
                session.execute(
                    delete(CampaignMember).where(CampaignMember.campaign_id == absorbed_id)
                )
            session.add(
                CampaignEvent(
                    campaign_id=survivor_id,
                    event_type="merge",
                    occurred_at=now,
                    related_campaign_codes=sorted(existing_by_id[a].code for a in absorbed_ids),
                    members_before=members_before,
                    members_after=members_after,
                )
            )
        counts.merged += 1
        handled_existing.add(survivor_id)
        handled_existing.update(absorbed_ids)
        handled_new.add(new_idx)

    # --- Splits: an existing campaign whose best match spans 2+ new components.
    existing_idx_to_new: dict[UUID, list[tuple[float, int]]] = defaultdict(list)
    for idx, best in new_best.items():
        if best is not None and idx not in handled_new:
            existing_idx_to_new[best[1]].append((best[0], idx))

    for camp_id, split_matches in sorted(
        existing_idx_to_new.items(), key=lambda kv: existing_by_id[kv[0]].code
    ):
        if camp_id in handled_existing or len(split_matches) < 2:
            continue
        split_ranked = sorted(split_matches, key=lambda m: (-m[0], m[1]))
        continuing_idx = split_ranked[0][1]
        other_indices = [m[1] for m in split_ranked[1:]]
        component, score, relation_types = qualifying[continuing_idx]
        members_before = sorted(str(i) for i in existing_members[camp_id])
        members_after = sorted(str(i) for i in component)

        new_codes: list[str] = []
        if not dry_run:
            campaign = existing_by_id[camp_id]
            _set_campaign_members(session, camp_id, component, now)
            campaign.score = score
            campaign.relation_types = sorted(relation_types)
            campaign.last_seen = now
        for other_idx in other_indices:
            other_component, other_score, other_relation_types = qualifying[other_idx]
            if not dry_run:
                new_campaign = _create_campaign(
                    session, other_component, other_score, other_relation_types, now
                )
                new_codes.append(new_campaign.code)
            counts.created += 1
            handled_new.add(other_idx)
        if not dry_run:
            session.add(
                CampaignEvent(
                    campaign_id=camp_id,
                    event_type="split",
                    occurred_at=now,
                    related_campaign_codes=sorted(new_codes),
                    members_before=members_before,
                    members_after=members_after,
                )
            )
        counts.split += 1
        handled_existing.add(camp_id)
        handled_new.add(continuing_idx)

    # --- Everything else: a simple 1:1 continuation or a brand-new campaign.
    def _sort_key(i: int) -> str:
        return sorted(str(x) for x in qualifying[i][0])[0]

    for idx in sorted(range(len(qualifying)), key=_sort_key):
        if idx in handled_new:
            continue
        component, score, relation_types = qualifying[idx]
        best = new_best[idx]
        if best is not None and best[1] not in handled_existing:
            if not dry_run:
                campaign = existing_by_id[best[1]]
                _set_campaign_members(session, best[1], component, now)
                campaign.score = score
                campaign.relation_types = sorted(relation_types)
                campaign.last_seen = now
            counts.updated += 1
        else:
            if not dry_run:
                _create_campaign(session, component, score, relation_types, now)
            counts.created += 1

    if not dry_run:
        _refresh_campaign_statuses(session, config)

    return counts


def run_clustering(
    session: Session,
    config: ClusteringConfig,
    *,
    relation_names: list[str] | None = None,
    label_index: LabelIndex | None = None,
    dry_run: bool = False,
) -> ClusterRunResult:
    names = sorted(relation_names) if relation_names else sorted(ALL_RELATIONS)

    edges_added = edges_updated = edges_removed = 0
    for name in names:
        relation = ALL_RELATIONS[name](config, label_index=label_index)
        candidates = sorted(
            relation.detect(session),
            key=lambda c: (str(c.src_indicator_id), str(c.dst_indicator_id)),
        )
        added, updated, removed = _sync_edges_for_relation(session, name, candidates)
        edges_added += added
        edges_updated += updated
        edges_removed += removed
        logger.info(
            "relation_detected", relation=name, added=added, updated=updated, removed=removed
        )

    graph = build_graph(session)
    components = sorted(
        (frozenset(c) for c in nx.connected_components(graph)),
        key=lambda c: sorted(str(x) for x in c)[0] if c else "",
    )

    qualifying: list[tuple[frozenset[UUID], float, set[str]]] = []
    for component in components:
        if len(component) < config.campaign.min_size:
            continue
        score, relation_types = score_component(graph, component, config.campaign)
        # Inclusive: a single shares_receiving_wallet edge (weight 1.0)
        # between exactly two nodes scores exactly at the default
        # threshold (1.0 / 2 nodes = 0.5) — the strongest single relation
        # this pipeline has must be able to form a campaign on its own,
        # so the boundary itself has to qualify, not just fall short of it.
        if score >= config.campaign.score_threshold:
            qualifying.append((component, score, relation_types))
    qualifying.sort(key=lambda q: sorted(str(x) for x in q[0])[0])

    counts = _match_and_persist_campaigns(session, qualifying, config, dry_run=dry_run)

    if dry_run:
        session.rollback()
    else:
        session.commit()

    result = ClusterRunResult(
        relations_run=names,
        edges_added=edges_added,
        edges_updated=edges_updated,
        edges_removed=edges_removed,
        components_considered=len(components),
        campaigns_created=counts.created,
        campaigns_updated=counts.updated,
        campaigns_merged=counts.merged,
        campaigns_split=counts.split,
        dry_run=dry_run,
    )
    logger.info("cluster_run_complete", **asdict(result))
    return result
