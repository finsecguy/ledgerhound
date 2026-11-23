"""Markdown + PDF report rendering from an approved assessment.

Twelve fixed sections, rendered from `templates/report.md.j2` in that
exact order (see the module's own numbered headers). Section 12,
Methodology & Limitations, is never optional and is entirely
auto-generated from the evidence pack (which relations linked the
campaign, trace depth, serving providers, any partial/truncated
results). It's what makes the report defensible instead of just a
narrative.

Pure functions of an already-fetched `(Campaign, Assessment,
EvidencePack)` triple: no DB session, no network, no LLM call. PDF
rendering via `weasyprint` is attempted lazily (imported only inside
`render_pdf`) so a `--format md` run never needs it importable at all;
if weasyprint (or the system libraries it depends on) isn't available,
`render_pdf` raises `ReportRenderError` with a clear message rather than
crashing the whole export layer's import.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import jinja2
import markdown as markdown_lib
import structlog

from ledgerhound import __author__ as PRODUCT_AUTHOR
from ledgerhound.assess.drafter import overall_confidence
from ledgerhound.assess.evidence import EvidencePack
from ledgerhound.db.models import Assessment, Campaign

logger = structlog.get_logger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=False,
)


class ReportRenderError(Exception):
    """Raised when a requested render step (currently: PDF) can't run."""


def render_campaign_dot(pack: EvidencePack) -> str:
    """Same DOT format as `lh cluster graph --format dot`, built directly
    from the evidence pack (no DB access needed) since the pack already
    carries every member and edge a campaign's graph needs."""
    labels = {m.ref: (m.value if len(m.value) <= 24 else m.value[:22] + "…") for m in pack.members}
    lines = ["graph campaign {"]
    for member in sorted(pack.members, key=lambda m: m.ref):
        lines.append(f'  "{member.ref}" [label="{labels[member.ref]}"];')
    for edge in sorted(pack.edges, key=lambda e: (e.src_ref, e.dst_ref, e.relation)):
        lines.append(f'  "{edge.src_ref}" -- "{edge.dst_ref}" [label="{edge.relation}"];')
    lines.append("}")
    return "\n".join(lines)


def render_graph_png(dot_source: str) -> bytes | None:
    """Render DOT to PNG via the system `dot` binary (Graphviz). Returns
    None. Never raises, if Graphviz isn't installed or errors, so the
    report falls back to embedding the DOT source as text instead of
    failing the whole render."""
    try:
        proc = subprocess.run(
            ["dot", "-Tpng"],
            input=dot_source.encode("utf-8"),
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.info("graphviz_unavailable", reason=str(exc))
        return None
    return proc.stdout


def _infrastructure_rows(pack: EvidencePack) -> list[dict[str, str]]:
    address_by_ref = {p.member_ref: p for p in pack.address_profiles}
    domain_by_ref = {d.member_ref: d for d in pack.domain_profiles}
    rows = []
    for member in sorted(pack.members, key=lambda m: (m.indicator_type, m.value)):
        detail = "-"
        if member.ref in address_by_ref:
            profile = address_by_ref[member.ref]
            detail = (
                f"chain={profile.chain}, tx_count={profile.tx_count}, "
                f"provider={profile.provider}"
            )
        elif member.ref in domain_by_ref:
            domain = domain_by_ref[member.ref]
            ns = ", ".join(domain.ns_records) if domain.ns_records else "-"
            detail = f"registrar={domain.registrar or '-'}, ns={ns}"
        rows.append({"type": member.indicator_type, "value": member.value, "detail": detail})
    return rows


def _indicators_of_compromise(pack: EvidencePack) -> list[dict[str, str]]:
    return [
        {
            "type": member.indicator_type,
            "value": member.defanged_value,
            "first_seen": member.first_seen,
            "last_seen": member.last_seen,
        }
        for member in sorted(pack.members, key=lambda m: (m.indicator_type, m.value))
    ]


def _partial_or_truncated_notes(pack: EvidencePack) -> list[str]:
    notes = []
    for trace in pack.traces:
        if trace.truncated:
            notes.append(
                f"Fund-flow trace rooted at {trace.member_ref} (depth {trace.depth}) was "
                "truncated by a breadth or depth cap. Downstream coverage may be incomplete."
            )
        if trace.summary.get("incomplete_due_to_provider_failure"):
            notes.append(
                f"Fund-flow trace rooted at {trace.member_ref} could not reach every "
                "counterparty because a chain-data provider failed mid-trace."
            )
    return notes


def build_report_context(
    campaign: Campaign,
    assessment: Assessment,
    pack: EvidencePack,
    *,
    tlp: str,
    stix_bundle_filename: str | None = None,
) -> tuple[dict[str, Any], bytes | None]:
    """Build the Jinja2 template context, plus the rendered graph PNG
    bytes (or None if Graphviz isn't available) for the caller to write
    alongside the report."""
    draft = assessment.draft
    graph_dot = render_campaign_dot(pack)
    graph_png = render_graph_png(graph_dot)
    graph_png_filename = f"{campaign.code}_graph.png" if graph_png is not None else None

    context = {
        "campaign": campaign,
        "assessment": assessment,
        "draft": draft,
        "tlp": tlp,
        "overall_confidence": overall_confidence(draft),
        "generated_at": assessment.reviewed_at,
        "analyst": assessment.reviewed_by,
        "author": PRODUCT_AUTHOR,
        "graph_dot": graph_dot,
        "graph_png_filename": graph_png_filename,
        "infrastructure_rows": _infrastructure_rows(pack),
        "iocs": _indicators_of_compromise(pack),
        "sources": sorted(pack.source_grades, key=lambda s: s.source_name),
        "traces": pack.traces,
        "relation_types": sorted({edge.relation for edge in pack.edges}),
        "providers": sorted({profile.provider for profile in pack.address_profiles}),
        "partial_or_truncated_notes": _partial_or_truncated_notes(pack),
        "stix_bundle_filename": stix_bundle_filename,
        "evidence_hash": assessment.evidence_hash,
    }
    return context, graph_png


def render_markdown(context: dict[str, Any]) -> str:
    template = _ENV.get_template("report.md.j2")
    return template.render(**context)


def render_pdf(markdown_text: str, *, base_url: str | None = None) -> bytes:
    """Convert already-rendered report Markdown to PDF via weasyprint.
    Imported lazily so a Markdown-only render never needs weasyprint (or
    the system Pango/Cairo libraries it depends on) importable at all."""
    try:
        import weasyprint
    except (ImportError, OSError) as exc:
        raise ReportRenderError(
            "PDF rendering requires weasyprint and its system libraries "
            f"(Pango/Cairo), which are not available: {exc}"
        ) from exc

    html_body = markdown_lib.markdown(markdown_text, extensions=["tables", "fenced_code"])
    html_doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<style>body{font-family:sans-serif} table{border-collapse:collapse} "
        "table,th,td{border:1px solid #999;padding:4px}</style>"
        f"</head><body>{html_body}</body></html>"
    )
    return weasyprint.HTML(string=html_doc, base_url=base_url).write_pdf()  # type: ignore[no-any-return]

