"""Structured LLM drafting of a campaign assessment.

The model is called through the `AssessmentLLM` socket (see
`assess/llm.py`) with a forced single tool-call turn, whose input schema
is generated directly from `AssessmentDraft`, so its response is always
JSON shaped like our schema rather than free text we'd have to parse.
That gets us schema-level validity for free; the hard constraints in the
milestone spec. Resolvable evidence refs, real ATT&CK ids, no
attribution without high-confidence support, and an exact arithmetic
match on the observed-inflow total. Are business rules pydantic can't
express, so `_validate_business_rules` checks them explicitly and a
failure raises `DraftValidationError` before anything is persisted:
nothing invalid is ever written to `assessments`, not even at a
"rejected" status.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.assess.attack import AttackDataset
from ledgerhound.assess.evidence import EvidencePack, build_evidence_pack, refresh_staleness
from ledgerhound.assess.llm import AssessmentLLM, LLMResponseError
from ledgerhound.assess.prompts import LATEST_PROMPT_VERSION, get_prompt
from ledgerhound.db.models import Assessment, Campaign

logger = structlog.get_logger(__name__)

Confidence = Literal["low", "moderate", "high"]


class KeyJudgement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str
    confidence: Confidence
    supporting_evidence_refs: list[str] = Field(default_factory=list)


class Targeting(BaseModel):
    model_config = ConfigDict(extra="forbid")

    victim_profile: str
    geographies: list[str] = Field(default_factory=list)
    impersonated_brands: list[str] = Field(default_factory=list)


class Ttp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    observation: str


class Financial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    narrative: str
    total_observed_inflow: str
    cashout_venues: list[str] = Field(default_factory=list)
    sanctions_exposure: str


class Attribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str | None = None
    confidence: Confidence | None = None
    rationale: str


class AssessmentDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_judgements: list[KeyJudgement]
    summary: str
    targeting: Targeting
    ttps: list[Ttp] = Field(default_factory=list)
    financial: Financial
    assessment: str
    attribution: Attribution
    outlook: str
    gaps: list[str] = Field(default_factory=list)


#: Ordering for `overall_confidence` below. Index position is rank.
CONFIDENCE_ORDER = ["low", "moderate", "high"]


def overall_confidence(draft: dict[str, Any]) -> str:
    """The draft schema has no single "overall confidence" field
    milestone 5's STIX/report export need one number anyway, so this
    takes the highest confidence among the assessment's key judgements
    (the most defensible single answer to "how confident is this
    overall"). Defaults to "low" if there are none. Shared by
    `export/stix.py` and `export/report.py` so both derive it the same
    way."""
    judgements = draft.get("key_judgements", [])
    if not judgements:
        return "low"
    confidences: list[str] = [j["confidence"] for j in judgements]
    return max(confidences, key=CONFIDENCE_ORDER.index)


class DraftBlockedError(Exception):
    """Raised when the evidence hash hasn't changed since the last
    version and the caller didn't pass --force."""


class DraftValidationError(Exception):
    """Raised when a draft (LLM-produced or human-edited) fails schema or
    business-rule validation. Nothing is persisted when this is raised."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def _validate_business_rules(
    draft: AssessmentDraft, pack: EvidencePack, attack_dataset: AttackDataset
) -> list[str]:
    errors: list[str] = []
    all_refs = pack.all_refs()

    for judgement in draft.key_judgements:
        for ref in judgement.supporting_evidence_refs:
            if ref not in all_refs:
                errors.append(f"key_judgements: unresolvable supporting_evidence_refs {ref!r}")

    for ttp in draft.ttps:
        if not attack_dataset.is_valid_id(ttp.technique_id):
            errors.append(f"ttps: unknown ATT&CK technique_id {ttp.technique_id!r}")

    if draft.attribution.claim is not None and not any(
        j.confidence == "high" for j in draft.key_judgements
    ):
        errors.append(
            "attribution.claim is set but no key_judgement has confidence='high' to support it"
        )

    try:
        drafted_inflow = Decimal(draft.financial.total_observed_inflow)
        expected_inflow = Decimal(pack.total_observed_inflow)
    except InvalidOperation:
        errors.append(
            f"financial.total_observed_inflow {draft.financial.total_observed_inflow!r} "
            "is not a valid number"
        )
    else:
        if drafted_inflow != expected_inflow:
            errors.append(
                f"financial.total_observed_inflow {draft.financial.total_observed_inflow!r} "
                f"does not match the evidence pack's computed value "
                f"{pack.total_observed_inflow!r}"
            )

    return errors


def parse_and_validate(
    raw: dict[str, Any], pack: EvidencePack, attack_dataset: AttackDataset
) -> AssessmentDraft:
    """Schema-validate `raw` into an `AssessmentDraft`, then apply the
    hard constraints code enforces beyond what the schema can express.
    Used both for a fresh LLM draft and for a human-edited one, an edit
    is re-validated exactly like a new draft, not trusted because a
    human touched it."""
    try:
        draft = AssessmentDraft.model_validate(raw)
    except ValidationError as exc:
        raise DraftValidationError([str(exc)]) from exc

    errors = _validate_business_rules(draft, pack, attack_dataset)
    if errors:
        raise DraftValidationError(errors)
    return draft


def draft_assessment(
    session: Session,
    campaign: Campaign,
    *,
    llm: AssessmentLLM,
    model: str,
    attack_dataset: AttackDataset,
    force: bool = False,
) -> Assessment:
    pack = build_evidence_pack(session, campaign)
    refresh_staleness(session, campaign.id, pack.evidence_hash)

    latest = session.scalar(
        select(Assessment)
        .where(Assessment.campaign_id == campaign.id)
        .order_by(Assessment.version.desc())
        .limit(1)
    )
    if latest is not None and latest.evidence_hash == pack.evidence_hash and not force:
        raise DraftBlockedError(
            f"Evidence for {campaign.code} is unchanged since version {latest.version} "
            "(pass --force to redraft anyway)."
        )

    prompt = get_prompt(LATEST_PROMPT_VERSION)
    try:
        raw_input = llm.draft(
            model=model,
            system=prompt.system,
            user_message=prompt.build_user_message(pack),
            tool_schema=AssessmentDraft.model_json_schema(),
        )
    except LLMResponseError as exc:
        raise DraftValidationError([str(exc)]) from exc
    draft = parse_and_validate(raw_input, pack, attack_dataset)

    next_version = (latest.version + 1) if latest is not None else 1
    row = Assessment(
        campaign_id=campaign.id,
        version=next_version,
        evidence_hash=pack.evidence_hash,
        prompt_version=prompt.version,
        model=model,
        draft=draft.model_dump(mode="json"),
        status="draft",
        edited_by_human=False,
        stale=False,
    )
    session.add(row)
    session.flush()
    logger.info("assessment_drafted", campaign=campaign.code, version=next_version)
    return row

