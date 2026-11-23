"""Response/request models for the assessment review workflow.

`draft`/`draft_a`/`draft_b` below are typed as `assess.drafter.
AssessmentDraft`, the exact same pydantic model `assess/drafter.py` and
`assess/review.py` validate against, rather than a hand-duplicated
shape. `openapi-typescript` generates the frontend's TypeScript type
from this same model via FastAPI's OpenAPI schema, so the dashboard's
form and the CLI's validation can never quietly drift apart.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from ledgerhound.assess.drafter import AssessmentDraft


class AssessmentVersionSummary(BaseModel):
    version: int
    status: str
    edited_by_human: bool
    stale: bool
    model: str
    prompt_version: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime


class AssessmentOut(BaseModel):
    version: int
    status: str
    stale: bool
    edited_by_human: bool
    model: str
    prompt_version: str
    evidence_hash: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    reviewer_notes: str | None
    draft: AssessmentDraft
    #: ref -> short human-readable description, from
    #: `assess.evidence.describe_refs`, so the review UI never shows a
    #: bare `member:<uuid>` string.
    evidence_ref_descriptions: dict[str, str]


class AssessmentDiffOut(BaseModel):
    version_a: int
    version_b: int
    draft_a: AssessmentDraft
    draft_b: AssessmentDraft
    unified_diff: str


class DraftRequest(BaseModel):
    force: bool = False


class ApproveRequest(BaseModel):
    notes: str
    reviewer: str | None = None
    force: bool = False


class RejectRequest(BaseModel):
    notes: str
    reviewer: str | None = None


class ValidationErrorOut(BaseModel):
    errors: list[str]


class AttackTechniqueOut(BaseModel):
    technique_id: str
    name: str


class AttackTechniquesOut(BaseModel):
    version: str
    techniques: list[AttackTechniqueOut]

