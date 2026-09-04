"""Report rendering: all twelve fixed sections in order, and a truncated
trace showing up explicitly in both section 7 (Financial Analysis) and
section 12 (Methodology & Limitations) — never silently omitted."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from ledgerhound.assess.evidence import build_evidence_pack
from ledgerhound.db.models import (
    Assessment,
    Campaign,
    CampaignMember,
    Indicator,
    IndicatorType,
    Trace,
    TraceNodeRow,
)
from ledgerhound.export.report import build_report_context, render_markdown

NOW = datetime(2026, 1, 1, tzinfo=UTC)

SECTION_HEADERS = [
    "# 1. LH-2026-001",
    "## 2. Key Judgements",
    "## 3. Summary",
    "## 4. Targeting",
    "## 5. Tradecraft (MITRE ATT&CK)",
    "## 6. Infrastructure",
    "## 7. Financial Analysis",
    "## 8. Assessment",
    "## 9. Outlook",
    "## 10. Indicators of Compromise",
    "## 11. Sources & Reliability",
    "## 12. Methodology & Limitations",
]


def _valid_draft(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "key_judgements": [
            {"statement": "Shares a wallet.", "confidence": "high", "supporting_evidence_refs": []}
        ],
        "summary": "A crypto scam campaign.",
        "targeting": {"victim_profile": "v", "geographies": [], "impersonated_brands": []},
        "ttps": [{"technique_id": "T1566", "technique_name": "Phishing", "observation": "o"}],
        "financial": {
            "narrative": "n",
            "total_observed_inflow": "0",
            "cashout_venues": [],
            "sanctions_exposure": "none",
        },
        "assessment": "a",
        "attribution": {"claim": None, "confidence": None, "rationale": "r"},
        "outlook": "o",
        "gaps": [],
    }
    base.update(overrides)
    return base


def _make_campaign_and_assessment(
    session: Session, *, with_truncated_trace: bool
) -> tuple[Campaign, Assessment, Any]:
    indicator = Indicator(
        type=IndicatorType.ETH_ADDRESS,
        value="0xA",
        defanged_value="0xA",
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(indicator)
    session.flush()

    campaign = Campaign(
        code="LH-2026-001",
        status="active",
        score=1.0,
        relation_types=["shares_receiving_wallet"],
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(campaign)
    session.flush()
    session.add(CampaignMember(campaign_id=campaign.id, indicator_id=indicator.id, joined_at=NOW))

    if with_truncated_trace:
        trace = Trace(
            root_indicator_id=indicator.id,
            depth=2,
            run_at=NOW,
            truncated=True,
            summary={
                "total_traced_value": "100",
                "terminal_counts": {"exchange": 1},
                "truncated": True,
                "incomplete_due_to_provider_failure": False,
            },
        )
        session.add(trace)
        session.flush()
        session.add(
            TraceNodeRow(
                trace_id=trace.id,
                address="0xA",
                hop=0,
                is_terminal=False,
                terminal_reason=None,
                labels=[],
            )
        )

    assessment = Assessment(
        campaign_id=campaign.id,
        version=1,
        evidence_hash="h",
        prompt_version="v1",
        model="claude-sonnet-4-5",
        draft=_valid_draft(),
        status="approved",
        reviewed_by="alice",
        reviewed_at=NOW,
        stale=False,
    )
    session.add(assessment)
    session.commit()

    pack = build_evidence_pack(session, campaign)
    return campaign, assessment, pack


def test_report_renders_all_twelve_sections_in_order(db_session: Session) -> None:
    campaign, assessment, pack = _make_campaign_and_assessment(
        db_session, with_truncated_trace=False
    )
    context, _graph_png = build_report_context(campaign, assessment, pack, tlp="TLP:CLEAR")
    markdown_text = render_markdown(context)

    positions = [markdown_text.index(header) for header in SECTION_HEADERS]
    assert positions == sorted(positions), "sections must appear in the fixed order"


def test_report_without_truncation_does_not_claim_truncation(db_session: Session) -> None:
    campaign, assessment, pack = _make_campaign_and_assessment(
        db_session, with_truncated_trace=False
    )
    context, _graph_png = build_report_context(campaign, assessment, pack, tlp="TLP:CLEAR")
    markdown_text = render_markdown(context)

    section_12 = markdown_text[markdown_text.index("## 12.") :]
    assert "None. All enrichment and trace data" in section_12
    assert "truncated by a breadth or depth cap" not in section_12


def test_truncated_trace_shown_in_financial_and_methodology_sections(db_session: Session) -> None:
    campaign, assessment, pack = _make_campaign_and_assessment(
        db_session, with_truncated_trace=True
    )
    context, _graph_png = build_report_context(campaign, assessment, pack, tlp="TLP:CLEAR")
    markdown_text = render_markdown(context)

    section_7 = markdown_text[markdown_text.index("## 7.") : markdown_text.index("## 8.")]
    assert "**Yes**" in section_7  # the Truncated column for this trace's row

    section_12 = markdown_text[markdown_text.index("## 12.") :]
    assert "truncated by a breadth or depth cap" in section_12
