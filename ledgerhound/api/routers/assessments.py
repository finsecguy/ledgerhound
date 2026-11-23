"""Assessment review workflow. Every rule is imported from `assess/`,
never re-expressed: `assess.drafter.draft_assessment` for drafting,
`assess.review.edit_assessment`/`approve_assessment`/`reject_assessment`
for the write endpoints, and the exact same exceptions the CLI catches
become the exact same HTTP status codes here, so the CLI and the
dashboard can never disagree about what's valid.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.api.deps import get_session
from ledgerhound.api.routers.campaigns import get_campaign_or_404
from ledgerhound.api.schemas.assessments import (
    ApproveRequest,
    AssessmentDiffOut,
    AssessmentOut,
    AssessmentVersionSummary,
    AttackTechniqueOut,
    AttackTechniquesOut,
    DraftRequest,
    RejectRequest,
)
from ledgerhound.assess.attack import (
    AttackDatasetUnavailableError,
    load_attack_dataset,
    load_cached_attack_dataset,
)
from ledgerhound.assess.drafter import (
    AssessmentDraft,
    DraftBlockedError,
    DraftValidationError,
    draft_assessment,
)
from ledgerhound.assess.evidence import build_evidence_pack, describe_refs
from ledgerhound.assess.llm import OpenAICompatibleLLM
from ledgerhound.assess.review import (
    AlreadyApprovedError,
    IllegalTransitionError,
    approve_assessment,
    edit_assessment,
    get_version,
    reject_assessment,
    render_diff,
)
from ledgerhound.db.models import Assessment, Campaign
from ledgerhound.settings import get_settings

router = APIRouter(prefix="/api/campaigns", tags=["assessments"])
attack_router = APIRouter(prefix="/api/attack", tags=["attack"])

_DEFAULT_DASHBOARD_REVIEWER = "dashboard"


def _assessment_out(assessment: Assessment, campaign: Campaign, session: Session) -> AssessmentOut:
    pack = build_evidence_pack(session, campaign)
    return AssessmentOut(
        version=assessment.version,
        status=assessment.status,
        stale=assessment.stale,
        edited_by_human=assessment.edited_by_human,
        model=assessment.model,
        prompt_version=assessment.prompt_version,
        evidence_hash=assessment.evidence_hash,
        reviewed_by=assessment.reviewed_by,
        reviewed_at=assessment.reviewed_at,
        reviewer_notes=assessment.reviewer_notes,
        draft=AssessmentDraft.model_validate(assessment.draft),
        evidence_ref_descriptions=describe_refs(pack),
    )


def _get_version_or_404(session: Session, campaign_id: UUID, version: int | None) -> Assessment:
    try:
        return get_version(session, campaign_id, version)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{code}/assessment", response_model=AssessmentOut)
def get_assessment(
    code: str,
    version: int | None = Query(None, description="Defaults to the latest version."),
    session: Session = Depends(get_session),
) -> AssessmentOut:
    campaign = get_campaign_or_404(session, code)
    assessment = _get_version_or_404(session, campaign.id, version)
    return _assessment_out(assessment, campaign, session)


@router.get("/{code}/assessment/versions", response_model=list[AssessmentVersionSummary])
def list_assessment_versions(
    code: str, session: Session = Depends(get_session)
) -> list[AssessmentVersionSummary]:
    campaign = get_campaign_or_404(session, code)
    rows = session.scalars(
        select(Assessment).where(Assessment.campaign_id == campaign.id).order_by(Assessment.version)
    )
    return [
        AssessmentVersionSummary(
            version=row.version,
            status=row.status,
            edited_by_human=row.edited_by_human,
            stale=row.stale,
            model=row.model,
            prompt_version=row.prompt_version,
            reviewed_by=row.reviewed_by,
            reviewed_at=row.reviewed_at,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.get("/{code}/assessment/diff", response_model=AssessmentDiffOut)
def diff_assessment(
    code: str,
    from_: int = Query(..., alias="from"),
    to: int = Query(...),
    session: Session = Depends(get_session),
) -> AssessmentDiffOut:
    campaign = get_campaign_or_404(session, code)
    version_a = _get_version_or_404(session, campaign.id, from_)
    version_b = _get_version_or_404(session, campaign.id, to)
    return AssessmentDiffOut(
        version_a=version_a.version,
        version_b=version_b.version,
        draft_a=AssessmentDraft.model_validate(version_a.draft),
        draft_b=AssessmentDraft.model_validate(version_b.draft),
        unified_diff=render_diff(version_a, version_b),
    )


@router.post("/{code}/assessment/draft", response_model=AssessmentOut, status_code=201)
def create_draft(
    code: str, body: DraftRequest, session: Session = Depends(get_session)
) -> AssessmentOut:
    campaign = get_campaign_or_404(session, code)
    settings = get_settings()
    if not settings.llm_api_key:
        raise HTTPException(
            status_code=400, detail="llm_api_key is not set (required only for drafting)."
        )

    attack_dataset = load_attack_dataset(settings.attack_stix_cache_path)
    llm = OpenAICompatibleLLM(api_key=settings.llm_api_key, base_url=settings.llm_base_url)
    try:
        assessment = draft_assessment(
            session,
            campaign,
            llm=llm,
            model=settings.llm_model,
            attack_dataset=attack_dataset,
            force=body.force,
        )
    except DraftBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DraftValidationError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
    return _assessment_out(assessment, campaign, session)


@router.put("/{code}/assessment/{version}", response_model=AssessmentOut)
def edit_draft(
    code: str, version: int, body: AssessmentDraft, session: Session = Depends(get_session)
) -> AssessmentOut:
    """The dashboard equivalent of `lh assess edit`: submits a full,
    schema-valid `AssessmentDraft` (FastAPI/pydantic already rejects a
    structurally invalid body before this handler runs) based on
    `version`; re-validated against every business rule via the same
    `edit_assessment` the CLI calls, and stored as a new version."""
    campaign = get_campaign_or_404(session, code)
    source = _get_version_or_404(session, campaign.id, version)
    settings = get_settings()
    try:
        attack_dataset = load_cached_attack_dataset(settings.attack_stix_cache_path)
    except AttackDatasetUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    try:
        new_assessment = edit_assessment(
            session, campaign, source, body.model_dump(mode="json"), attack_dataset=attack_dataset
        )
    except DraftValidationError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
    return _assessment_out(new_assessment, campaign, session)


@router.post("/{code}/assessment/{version}/approve", response_model=AssessmentOut)
def approve(
    code: str, version: int, body: ApproveRequest, session: Session = Depends(get_session)
) -> AssessmentOut:
    campaign = get_campaign_or_404(session, code)
    reviewer = body.reviewer or _DEFAULT_DASHBOARD_REVIEWER
    try:
        assessment = approve_assessment(
            session,
            campaign,
            version=version,
            reviewer=reviewer,
            notes=body.notes,
            force=body.force,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (IllegalTransitionError, AlreadyApprovedError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _assessment_out(assessment, campaign, session)


@router.post("/{code}/assessment/{version}/reject", response_model=AssessmentOut)
def reject(
    code: str, version: int, body: RejectRequest, session: Session = Depends(get_session)
) -> AssessmentOut:
    campaign = get_campaign_or_404(session, code)
    reviewer = body.reviewer or _DEFAULT_DASHBOARD_REVIEWER
    try:
        assessment = reject_assessment(
            session, campaign, version=version, reviewer=reviewer, notes=body.notes
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IllegalTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _assessment_out(assessment, campaign, session)


@attack_router.get("/techniques", response_model=AttackTechniquesOut)
def list_attack_techniques() -> AttackTechniquesOut:
    """The cached ATT&CK technique list, for the review page's TTP
    autocomplete. Client-side rejection of an unknown technique id
    before submit, mirroring (not replacing) the server-side check
    `assess/drafter.py` still enforces on save."""
    settings = get_settings()
    try:
        dataset = load_cached_attack_dataset(settings.attack_stix_cache_path)
    except AttackDatasetUnavailableError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    techniques = [
        AttackTechniqueOut(technique_id=technique_id, name=name)
        for technique_id, name in sorted(dataset.techniques.items())
    ]
    return AttackTechniquesOut(version=dataset.version, techniques=techniques)

