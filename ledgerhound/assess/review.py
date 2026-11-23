"""Draft -> review -> approve/reject workflow.

State machine, per version row:

    draft ----+--> approved
              |
    in_review-+--> rejected

`approve` is legal from "draft" or "in_review"; `reject` is legal from
"draft", "in_review", or "approved" (an analyst revoking a prior
approval after finding a problem); neither is legal from "rejected"
fixing a rejected version means editing or re-drafting to produce a new
one, never resurrecting the old row. Approving an already-approved
version, or a version that's already been rejected, is also illegal
both raise `IllegalTransitionError`.

"Exactly one approved version per campaign" is enforced twice: the
database has a partial unique index (`0006_assessments`) as the
ultimate guarantee, and `approve_assessment` checks for an existing
approved version first so a conflict produces a clear
`AlreadyApprovedError` instead of an opaque `IntegrityError`. Pass
`force=True` to explicitly supersede it (the old version is marked
"rejected" with a note, never silently discarded).
"""

from __future__ import annotations

import difflib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.assess.attack import AttackDataset
from ledgerhound.assess.drafter import parse_and_validate
from ledgerhound.assess.evidence import build_evidence_pack, refresh_staleness
from ledgerhound.db.models import Assessment, Campaign

_APPROVABLE_FROM = {"draft", "in_review"}
_REJECTABLE_FROM = {"draft", "in_review", "approved"}


class IllegalTransitionError(Exception):
    """Raised when a review action is attempted from a status that
    doesn't allow it."""


class AlreadyApprovedError(Exception):
    """Raised by `approve_assessment` when a different version is
    already approved and `force` wasn't passed."""


def get_version(session: Session, campaign_id: UUID, version: int | None) -> Assessment:
    """The named version, or (version=None) the latest one, for a campaign."""
    query = select(Assessment).where(Assessment.campaign_id == campaign_id)
    query = (
        query.where(Assessment.version == version)
        if version is not None
        else query.order_by(Assessment.version.desc()).limit(1)
    )
    row = session.scalar(query)
    if row is None:
        target = f"version {version}" if version is not None else "any version"
        raise LookupError(f"No assessment ({target}) found for this campaign.")
    return row


def edit_assessment(
    session: Session,
    campaign: Campaign,
    source: Assessment,
    edited_raw: dict[str, Any],
    *,
    attack_dataset: AttackDataset,
) -> Assessment:
    """Re-validate a human-edited draft and store it as a new version.

    Always validated against a freshly-built evidence pack, not the
    source version's: an edited citation must resolve against evidence
    as it stands right now, and any resulting evidence-hash difference
    is exactly what `stale` on a since-approved version exists to catch.
    """
    pack = build_evidence_pack(session, campaign)
    refresh_staleness(session, campaign.id, pack.evidence_hash)
    draft = parse_and_validate(edited_raw, pack, attack_dataset)

    latest = get_version(session, campaign.id, None)
    row = Assessment(
        campaign_id=campaign.id,
        version=latest.version + 1,
        evidence_hash=pack.evidence_hash,
        prompt_version=source.prompt_version,
        model=source.model,
        draft=draft.model_dump(mode="json"),
        status="in_review",
        edited_by_human=True,
        stale=False,
    )
    session.add(row)
    session.flush()
    return row


def approve_assessment(
    session: Session,
    campaign: Campaign,
    *,
    version: int | None,
    reviewer: str,
    notes: str,
    force: bool = False,
) -> Assessment:
    target = get_version(session, campaign.id, version)
    if target.status not in _APPROVABLE_FROM:
        raise IllegalTransitionError(
            f"Cannot approve version {target.version}: status is {target.status!r}, "
            f"must be one of {sorted(_APPROVABLE_FROM)}."
        )

    existing_approved = session.scalar(
        select(Assessment).where(
            Assessment.campaign_id == campaign.id,
            Assessment.status == "approved",
            Assessment.id != target.id,
        )
    )
    now = datetime.now(UTC)
    if existing_approved is not None:
        if not force:
            raise AlreadyApprovedError(
                f"{campaign.code} already has an approved version "
                f"({existing_approved.version}); pass --force to supersede it."
            )
        existing_approved.status = "rejected"
        existing_approved.reviewed_by = reviewer
        existing_approved.reviewed_at = now
        existing_approved.reviewer_notes = f"Superseded by version {target.version}."
        # Flushed separately, before `target` is promoted below: the two
        # updates land in the same flush's UPDATE batch in undefined
        # order otherwise, and if the promotion is applied first the
        # partial unique index (0006_assessments) briefly sees two
        # 'approved' rows for this campaign and rejects it outright.
        session.flush()

    target.status = "approved"
    target.reviewed_by = reviewer
    target.reviewed_at = now
    target.reviewer_notes = notes
    target.stale = False
    session.flush()
    return target


def reject_assessment(
    session: Session, campaign: Campaign, *, version: int | None, reviewer: str, notes: str
) -> Assessment:
    target = get_version(session, campaign.id, version)
    if target.status not in _REJECTABLE_FROM:
        raise IllegalTransitionError(
            f"Cannot reject version {target.version}: status is already {target.status!r}."
        )
    target.status = "rejected"
    target.reviewed_by = reviewer
    target.reviewed_at = datetime.now(UTC)
    target.reviewer_notes = notes
    session.flush()
    return target


def render_diff(a: Assessment, b: Assessment) -> str:
    a_lines = json.dumps(a.draft, indent=2, sort_keys=True).splitlines(keepends=True)
    b_lines = json.dumps(b.draft, indent=2, sort_keys=True).splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(a_lines, b_lines, fromfile=f"v{a.version}", tofile=f"v{b.version}")
    )

