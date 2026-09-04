"""Ledgerhound CLI. Exposed as both `ledgerhound` and `lh`."""

from __future__ import annotations

import asyncio
import getpass
import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import structlog
import typer
import yaml
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ledgerhound import config_store
from ledgerhound.assess.attack import (
    AttackDatasetUnavailableError,
    load_attack_dataset,
    load_cached_attack_dataset,
)
from ledgerhound.assess.drafter import DraftBlockedError, DraftValidationError, draft_assessment
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
from ledgerhound.cluster.campaigns import run_clustering
from ledgerhound.cluster.graph import explain_indicator
from ledgerhound.cluster.relations import ALL_RELATIONS, load_label_index
from ledgerhound.collect import REGISTRY, upsert_source
from ledgerhound.db.models import (
    Campaign,
    CampaignEvent,
    CampaignMember,
    Edge,
    Indicator,
    IndicatorType,
    Publication,
    Source,
    Trace,
    TraceEdgeRow,
    TraceNodeRow,
)
from ledgerhound.db.session import session_scope
from ledgerhound.enrich.base import Chain, Provider
from ledgerhound.enrich.chain.btc import BlockstreamProvider, MempoolSpaceProvider
from ledgerhound.enrich.chain.eth import BlockscoutEthProvider, PublicRpcEthProvider
from ledgerhound.enrich.chain.sol import PublicNodeSolProvider, SolanaRpcProvider
from ledgerhound.enrich.chain.trace import (
    DEFAULT_BREADTH,
    DEFAULT_DEPTH,
    HARD_DEPTH_CEILING,
    Tracer,
    TraceResult,
)
from ledgerhound.enrich.chain.tron import TronGridProvider, TronscanProvider
from ledgerhound.enrich.infra.certs import CrtShProvider
from ledgerhound.enrich.infra.dns import CloudflareDohProvider, DnsResolverProvider
from ledgerhound.enrich.infra.http import HttpFingerprintProvider
from ledgerhound.enrich.infra.whois import IanaBootstrapRdapProvider, RdapOrgProvider, WhoisProvider
from ledgerhound.enrich.labels.known import KnownAddressIndex
from ledgerhound.enrich.labels.ofac import OFACList, OFACSource
from ledgerhound.enrich.registry import ProviderRegistry
from ledgerhound.enrich.scheduler import SchedulerRunResult, TokenBucket, run_enrichment
from ledgerhound.export.feed import build_campaign_entry, write_feed
from ledgerhound.export.gate import (
    NotPublishableError,
    get_publishable_assessment,
    list_publishable_campaigns,
)
from ledgerhound.export.misp import build_misp_event, serialize_event, write_misp_feed
from ledgerhound.export.report import (
    ReportRenderError,
    build_report_context,
    render_markdown,
    render_pdf,
)
from ledgerhound.export.stix import StixExportError, build_campaign_bundle, serialize_bundle
from ledgerhound.extract.indicators import (
    validate_btc_bech32,
    validate_btc_legacy,
    validate_eth_address,
    validate_sol_address,
    validate_tron_address,
)
from ledgerhound.extract.pipeline import run_extraction
from ledgerhound.settings import Settings, get_settings
from ledgerhound.stats import compute_stats

logger = structlog.get_logger(__name__)

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="ledgerhound",
    help="Crypto-scam campaign intelligence pipeline.",
    no_args_is_help=True,
    add_completion=False,
)
db_app = typer.Typer(help="Database schema management.")
app.add_typer(db_app, name="db")
cluster_app = typer.Typer(help="Indicator clustering into campaigns.")
app.add_typer(cluster_app, name="cluster")
assess_app = typer.Typer(help="LLM-drafted campaign assessments with human review.")
app.add_typer(assess_app, name="assess")
export_app = typer.Typer(help="STIX 2.1 / MISP / IOC-feed export of publishable campaigns.")
app.add_typer(export_app, name="export")
report_app = typer.Typer(help="Markdown/PDF campaign reports.")
app.add_typer(report_app, name="report")
config_app = typer.Typer(help="View and edit GUI/CLI-shared runtime config.")
app.add_typer(config_app, name="config")


def _configure_logging() -> None:
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    # Logs go to stderr, never stdout: `lh trace --format json|dot` writes
    # machine-readable output to stdout for piping to jq/dot/a file, and
    # that stream must never be interleaved with log lines (ours or a
    # dependency's, e.g. httpx's per-request INFO logs).
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level)
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if settings.log_json
        else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


@app.callback()
def _main_callback() -> None:
    _configure_logging()


def _find_alembic_ini() -> Path:
    candidates = [
        Path.cwd() / "alembic.ini",
        Path(__file__).resolve().parent.parent / "alembic.ini",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise typer.BadParameter(
        "Could not locate alembic.ini (looked in cwd and the repo root). "
        "Run `lh db upgrade` from the ledgerhound project root."
    )


def _build_registry(client: httpx.AsyncClient, settings: Settings) -> ProviderRegistry:
    """Wire up every concrete provider into its facet's fallback chain.

    This is the one place all of `enrich/chain/*` and `enrich/infra/*` get
    instantiated — `enrich/registry.py` itself only knows about the
    `Provider` abstraction, not any specific implementation, so it can't
    (and shouldn't) do this wiring.
    """
    chains: dict[str, list[Provider]] = {
        "btc_address": [MempoolSpaceProvider(client=client), BlockstreamProvider(client=client)],
        "eth_address": [
            BlockscoutEthProvider(client=client),
            PublicRpcEthProvider(client=client),
        ],
        "tron_address": [TronGridProvider(client=client), TronscanProvider(client=client)],
        "sol_address": [SolanaRpcProvider(client=client), PublicNodeSolProvider(client=client)],
        "domain_dns": [DnsResolverProvider(client=client), CloudflareDohProvider(client=client)],
        "domain_rdap": [
            IanaBootstrapRdapProvider(client=client, cache_path=settings.rdap_bootstrap_cache_path),
            RdapOrgProvider(client=client),
            WhoisProvider(client=client),
        ],
        "domain_certs": [CrtShProvider(client=client)],
        "domain_http": [HttpFingerprintProvider(client=client)],
    }

    with session_scope() as session:
        overrides = config_store.get_providers_config(session)

    rate_limiters: dict[str, TokenBucket] = {}
    for providers in chains.values():
        for provider in providers:
            if provider.name in rate_limiters:
                continue
            override = overrides.get(provider.name)
            max_requests = override.max_requests if override else provider.rate_limit.max_requests
            per_seconds = override.per_seconds if override else provider.rate_limit.per_seconds
            rate_limiters[provider.name] = TokenBucket(max_requests, per_seconds)

    return ProviderRegistry(chains, rate_limiters=rate_limiters)


async def _load_labels(
    client: httpx.AsyncClient, settings: Settings
) -> tuple[OFACList | None, KnownAddressIndex]:
    known = (
        KnownAddressIndex.load(settings.known_addresses_path)
        if settings.known_addresses_path
        else KnownAddressIndex.load()
    )
    ofac_source = OFACSource(client, cache_path=settings.ofac_cache_path)
    try:
        ofac = await ofac_source.load()
    except Exception as exc:  # noqa: BLE001 - OFAC being unreachable shouldn't block enrichment
        err_console.print(
            f"[yellow]Could not load OFAC SDN list: {exc}. Continuing without it.[/yellow]"
        )
        ofac = None
    return ofac, known


def _detect_chain(address: str) -> Chain | None:
    """Best-effort chain detection from address shape, so `lh trace` only
    needs one positional argument. Order matters: ETH's `0x` prefix and
    TRON's `T` prefix are unambiguous, so check those before the broader
    base58 shapes that BTC/SOL share."""
    if address.startswith("0x") and validate_eth_address(address):
        return "eth"
    if address.startswith("T") and validate_tron_address(address):
        return "tron"
    if address.startswith(("1", "3")) and validate_btc_legacy(address):
        return "btc"
    if address.lower().startswith("bc1") and validate_btc_bech32(address):
        return "btc"
    if validate_sol_address(address):
        return "sol"
    return None


def _edge_sort_key(edge: Edge) -> tuple[str, str, str]:
    return (str(edge.src_indicator_id), str(edge.dst_indicator_id), edge.relation.value)


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Run all pending Alembic migrations."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(_find_alembic_ini()))
    command.upgrade(cfg, "head")
    console.print("[green]Database schema is up to date.[/green]")


@app.command("collect")
def collect(
    source: str | None = typer.Option(
        None, "--source", help="Run a single named source (must exist in config/sources.yaml)."
    ),
    run_all: bool = typer.Option(
        False, "--all", help="Run every enabled source in config/sources.yaml."
    ),
) -> None:
    """Fetch and store new raw reports from one or all configured sources."""
    if bool(source) == run_all:
        raise typer.BadParameter("Specify exactly one of --source NAME or --all.")

    settings = get_settings()

    with session_scope() as session:
        configs = config_store.get_sources_config(session)
        by_name = {c.name: c for c in configs}

        if source is not None:
            if source not in by_name:
                raise typer.BadParameter(
                    f"Unknown source {source!r}. Configured sources: {sorted(by_name)}"
                )
            targets = [by_name[source]]
        else:
            targets = [c for c in configs if c.enabled]

        # Keep the sources table in sync with the config registry regardless
        # of which subset we're about to run.
        for config in configs:
            upsert_source(session, config)
        session.flush()

        for config in targets:
            collector_cls = REGISTRY.get(config.name)
            if collector_cls is None:
                err_console.print(
                    f"[yellow]No collector implementation registered for "
                    f"{config.name!r}; skipping.[/yellow]"
                )
                continue
            source_row = session.scalar(select(Source).where(Source.name == config.name))
            assert source_row is not None  # just upserted above
            result = collector_cls(settings=settings).run(session, source_row)
            console.print(
                f"[bold]{result.source_name}[/bold]: fetched={result.fetched} "
                f"inserted={result.inserted} skipped_duplicate={result.skipped_duplicate} "
                f"failed={result.failed}"
            )


@app.command("extract")
def extract(
    since: datetime | None = typer.Option(
        None,
        "--since",
        help="Only process raw reports fetched at/after this timestamp (ISO 8601, UTC assumed).",
    ),
) -> None:
    """Run indicator extraction over stored raw reports."""
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=UTC)

    with session_scope() as session:
        result = run_extraction(session, since=since)

    console.print(
        f"reports_processed={result.reports_processed} "
        f"indicators_created={result.indicators_created} "
        f"indicators_reused={result.indicators_reused} "
        f"observations_created={result.observations_created} "
        f"observations_already_present={result.observations_already_present} "
        f"rejected_ip_count={result.rejected_ip_count}"
    )


@app.command("enrich")
def enrich(
    types: list[str] = typer.Option(
        [],
        "--type",
        help="Limit to this indicator type (repeatable). Default: all enrichable types.",
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="Force a single named provider, skipping its fallback chain."
    ),
    limit: int | None = typer.Option(
        None, "--limit", help="Max number of indicators to enrich this run."
    ),
    force: bool = typer.Option(False, "--force", help="Re-enrich even if not yet stale."),
) -> None:
    """Enrich indicators that have never been enriched, or whose enrichment
    has gone stale (older than the configured TTL)."""
    settings = get_settings()

    indicator_types: set[IndicatorType] | None = None
    if types:
        indicator_types = set()
        for raw in types:
            try:
                indicator_types.add(IndicatorType(raw))
            except ValueError as exc:
                valid = [t.value for t in IndicatorType]
                raise typer.BadParameter(f"Unknown indicator type {raw!r}. Valid: {valid}") from exc

    async def _run() -> SchedulerRunResult:
        async with httpx.AsyncClient(
            headers={"User-Agent": settings.http_user_agent}, timeout=settings.http_timeout_seconds
        ) as client:
            registry = _build_registry(client, settings)
            if provider is not None:
                registry = registry.restricted_to(provider)
                if not registry.facets():
                    raise typer.BadParameter(f"No facet uses provider {provider!r}.")
            ofac, known = await _load_labels(client, settings)
            with session_scope() as session:
                runtime_config = config_store.get_runtime_config(session)
                return await run_enrichment(
                    session,
                    registry,
                    indicator_types=indicator_types,
                    limit=limit,
                    force=force,
                    ttl=timedelta(hours=runtime_config.enrich_default_ttl_hours),
                    concurrency=runtime_config.enrich_concurrency,
                    ofac=ofac,
                    known=known,
                )

    result = asyncio.run(_run())
    console.print(
        f"attempted={result.attempted} succeeded={result.succeeded} "
        f"failed={result.failed} skipped_no_provider={result.skipped_no_provider}"
    )


def _trace_result_to_json(result: TraceResult) -> str:
    def default(value: Any) -> Any:
        if isinstance(value, Decimal):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError(f"not JSON serializable: {value!r}")

    payload = {
        "root_address": result.root_address,
        "chain": result.chain,
        "depth": result.depth,
        "breadth": result.breadth,
        "nodes": [asdict(n) for n in result.nodes],
        "edges": [asdict(e) for e in result.edges],
        "summary": asdict(result.summary),
    }
    return json.dumps(payload, default=default, indent=2)


def _trace_result_to_table(result: TraceResult) -> Table:
    table = Table(title=f"Trace from {result.root_address} ({result.chain})")
    table.add_column("Hop", justify="right")
    table.add_column("Address")
    table.add_column("Terminal")
    table.add_column("Labels")
    for node in result.nodes:
        labels = ", ".join(f"{label.label} ({label.label_type})" for label in node.labels)
        table.add_row(
            str(node.hop),
            node.address,
            node.terminal_reason or ("-" if not node.is_terminal else "yes"),
            labels or "-",
        )
    return table


def _trace_result_to_dot(result: TraceResult) -> str:
    lines = ["digraph trace {"]
    for node in result.nodes:
        shape = "doublecircle" if node.is_terminal else "circle"
        label = node.address if len(node.address) <= 12 else node.address[:10] + "…"
        lines.append(f'  "{node.address}" [shape={shape}, label="{label}"];')
    for edge in result.edges:
        lines.append(f'  "{edge.src}" -> "{edge.dst}" [label="{edge.value}"];')
    lines.append("}")
    return "\n".join(lines)


_INDICATOR_TYPE_BY_CHAIN: dict[Chain, IndicatorType] = {
    "btc": IndicatorType.BTC_ADDRESS,
    "eth": IndicatorType.ETH_ADDRESS,
    "tron": IndicatorType.TRON_ADDRESS,
    "sol": IndicatorType.SOL_ADDRESS,
}


def _persist_trace_result(session: Session, indicator_id: UUID, result: TraceResult) -> None:
    """Persist a trace run to `traces`/`trace_nodes`/`trace_edges`.

    Milestone 2 computed all of this in memory purely to print it —
    `cluster.relations.cashout`'s `shares_cashout_path` detector needs it
    on disk (two different indicators reaching the same labeled terminal
    node), so every trace against a tracked indicator is now persisted,
    not just displayed.
    """
    now = datetime.now(UTC)
    trace_row = Trace(
        root_indicator_id=indicator_id,
        depth=result.depth,
        run_at=now,
        truncated=result.summary.truncated,
        summary={
            "total_traced_value": str(result.summary.total_traced_value),
            "terminal_counts": result.summary.terminal_counts,
            "truncated": result.summary.truncated,
            "incomplete_due_to_provider_failure": result.summary.incomplete_due_to_provider_failure,
        },
    )
    session.add(trace_row)
    session.flush()

    for node in result.nodes:
        session.add(
            TraceNodeRow(
                trace_id=trace_row.id,
                address=node.address,
                hop=node.hop,
                is_terminal=node.is_terminal,
                terminal_reason=node.terminal_reason,
                labels=[label.model_dump() for label in node.labels],
            )
        )
    for edge in result.edges:
        session.add(
            TraceEdgeRow(
                trace_id=trace_row.id,
                src_address=edge.src,
                dst_address=edge.dst,
                hop=edge.hop,
                value=edge.value,
                tx_count=edge.tx_count,
            )
        )
    session.commit()


@app.command("trace")
def trace(
    address: str = typer.Argument(
        ..., help="Root chain address to trace downstream fund flow from."
    ),
    depth: int = typer.Option(
        DEFAULT_DEPTH, "--depth", min=1, max=HARD_DEPTH_CEILING, help="Max hops downstream."
    ),
    breadth: int = typer.Option(
        DEFAULT_BREADTH, "--breadth", min=1, help="Max counterparties followed per hop."
    ),
    output_format: str = typer.Option(
        "table", "--format", help="Output format: json, table, or dot."
    ),
) -> None:
    """Trace an address's downstream fund flow up to --depth hops.

    If `address` is a tracked indicator, the run is persisted (traces,
    trace_nodes, trace_edges) so `lh cluster run` can later detect shared
    cashout paths across different indicators — not just printed.
    """
    if output_format not in ("json", "table", "dot"):
        raise typer.BadParameter("--format must be one of: json, table, dot")

    chain = _detect_chain(address)
    if chain is None:
        raise typer.BadParameter(
            f"Could not determine chain for {address!r} (invalid or unsupported address)."
        )

    settings = get_settings()

    async def _run() -> TraceResult:
        async with httpx.AsyncClient(
            headers={"User-Agent": settings.http_user_agent}, timeout=settings.http_timeout_seconds
        ) as client:
            registry = _build_registry(client, settings)
            ofac, known = await _load_labels(client, settings)
            tracer = Tracer(registry, ofac=ofac, known=known)
            return await tracer.trace(address, chain, depth=depth, breadth=breadth)

    result = asyncio.run(_run())

    with session_scope() as session:
        indicator = session.scalar(
            select(Indicator).where(
                Indicator.type == _INDICATOR_TYPE_BY_CHAIN[chain], Indicator.value == address
            )
        )
        if indicator is not None:
            _persist_trace_result(session, indicator.id, result)
            persisted = True
        else:
            persisted = False

    if output_format == "json":
        # Plain print, not console.print: json/dot are for piping to a
        # file or another tool (jq, dot -Tpng), and rich's console would
        # inject ANSI highlighting/soft-wrapping into the output.
        print(_trace_result_to_json(result))
    elif output_format == "dot":
        print(_trace_result_to_dot(result))
    else:
        console.print(_trace_result_to_table(result))
        console.print(
            f"Total traced value: {result.summary.total_traced_value} | "
            f"Terminal counts: {result.summary.terminal_counts} | "
            f"Truncated: {result.summary.truncated}"
        )
        if result.summary.truncated:
            console.print(
                "[yellow]Coverage may be incomplete: a breadth or depth cap was hit.[/yellow]"
            )
        if not persisted:
            console.print(
                f"[yellow]{address!r} is not a tracked indicator; this trace was not "
                "persisted.[/yellow]"
            )


@app.command("providers")
def providers_cmd() -> None:
    """Show configured providers, their facets, and current health.

    Health is tracked in-memory for the life of a single command
    invocation, so a standalone run always shows every provider healthy —
    this is most useful immediately after (or piped alongside) `lh enrich`
    in a long-lived process, not as a persisted historical record.
    """
    settings = get_settings()

    async def _run() -> list[dict[str, Any]]:
        async with httpx.AsyncClient(
            headers={"User-Agent": settings.http_user_agent}, timeout=settings.http_timeout_seconds
        ) as client:
            registry = _build_registry(client, settings)
            return registry.health_snapshot()

    rows = asyncio.run(_run())
    table = Table(title="Providers")
    table.add_column("Provider")
    table.add_column("Facets")
    table.add_column("Healthy")
    table.add_column("Consecutive failures", justify="right")
    table.add_column("Last success")
    table.add_column("Cooldown until")
    for row in rows:
        table.add_row(
            row["provider"],
            ", ".join(row["facets"]),
            "yes" if row["healthy"] else "no",
            str(row["consecutive_failures"]),
            row["last_success"].isoformat() if row["last_success"] else "-",
            row["cooldown_until"].isoformat() if row["cooldown_until"] else "-",
        )
    console.print(table)


@app.command("stats")
def stats() -> None:
    """Print collection and extraction summary statistics."""
    settings = get_settings()
    with session_scope() as session:
        result = compute_stats(session, settings)

    source_table = Table(title="Sources")
    source_table.add_column("Source")
    source_table.add_column("Raw reports", justify="right")
    source_table.add_column("Last fetch (UTC)")
    for source in result.sources:
        source_table.add_row(
            source.name,
            str(source.raw_report_count),
            source.last_fetch.isoformat() if source.last_fetch else "-",
        )

    indicator_table = Table(title="Indicators by type")
    indicator_table.add_column("Type")
    indicator_table.add_column("Count", justify="right")
    for indicator_row in result.indicators_by_type:
        indicator_table.add_row(indicator_row.type, str(indicator_row.count))

    coverage_table = Table(title="Enrichment coverage")
    coverage_table.add_column("Type")
    coverage_table.add_column("Total", justify="right")
    coverage_table.add_column("Enriched", justify="right")
    coverage_table.add_column("Coverage", justify="right")
    coverage_table.add_column("Stale", justify="right")
    for coverage_row in result.enrichment_coverage:
        coverage_table.add_row(
            coverage_row.type,
            str(coverage_row.total),
            str(coverage_row.enriched),
            f"{coverage_row.coverage_pct:.0f}%",
            str(coverage_row.stale),
        )

    label_table = Table(title="Labels by type")
    label_table.add_column("Label type")
    label_table.add_column("Count", justify="right")
    for label_row in result.labels_by_type:
        label_table.add_row(label_row.label_type, str(label_row.count))

    console.print(source_table)
    console.print(indicator_table)
    console.print(f"Total unique indicators: {result.total_indicators}")
    console.print(f"Indicators seen in more than one source: {result.multi_source_indicator_count}")
    console.print(coverage_table)
    console.print(label_table)


@cluster_app.command("run")
def cluster_run(
    relation: list[str] = typer.Option(
        [], "--relation", help="Limit to this relation (repeatable). Default: all five."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would change without persisting anything."
    ),
) -> None:
    """Detect relations, sync the edge graph, and (re)compute campaigns."""
    if relation:
        unknown = sorted(set(relation) - set(ALL_RELATIONS))
        if unknown:
            raise typer.BadParameter(
                f"Unknown relation(s): {unknown}. Valid: {sorted(ALL_RELATIONS)}"
            )

    settings = get_settings()
    label_index = load_label_index(
        ofac_cache_path=settings.ofac_cache_path, known_addresses_path=settings.known_addresses_path
    )

    with session_scope() as session:
        config = config_store.get_clustering_config(session)
        result = run_clustering(
            session,
            config,
            relation_names=relation or None,
            label_index=label_index,
            dry_run=dry_run,
        )

    console.print(f"Relations run: {', '.join(result.relations_run)}")
    console.print(
        f"Edges: +{result.edges_added} added, ~{result.edges_updated} updated, "
        f"-{result.edges_removed} removed"
    )
    console.print(f"Components considered: {result.components_considered}")
    console.print(
        f"Campaigns: +{result.campaigns_created} created, ~{result.campaigns_updated} updated, "
        f"{result.campaigns_merged} merged, {result.campaigns_split} split"
    )
    if dry_run:
        console.print("[yellow]Dry run: nothing was persisted.[/yellow]")


@cluster_app.command("campaigns")
def cluster_campaigns_cmd(
    status: str | None = typer.Option(None, "--status", help="Filter: active or dormant."),
    min_size: int = typer.Option(0, "--min-size", help="Only campaigns with at least N members."),
) -> None:
    """List campaigns."""
    if status is not None and status not in ("active", "dormant"):
        raise typer.BadParameter("--status must be 'active' or 'dormant'")

    with session_scope() as session:
        query = select(Campaign).order_by(Campaign.code)
        if status:
            query = query.where(Campaign.status == status)
        campaigns = list(session.scalars(query))

        table = Table(title="Campaigns")
        table.add_column("Code")
        table.add_column("Display name")
        table.add_column("Status")
        table.add_column("Score", justify="right")
        table.add_column("Members", justify="right")
        table.add_column("Relations")
        table.add_column("Last seen")

        for campaign in campaigns:
            member_count = (
                session.scalar(
                    select(func.count(CampaignMember.id)).where(
                        CampaignMember.campaign_id == campaign.id
                    )
                )
                or 0
            )
            if member_count < min_size:
                continue
            table.add_row(
                campaign.code,
                campaign.display_name or "-",
                campaign.status,
                f"{campaign.score:.2f}",
                str(member_count),
                ", ".join(campaign.relation_types),
                campaign.last_seen.isoformat(),
            )

    console.print(table)


@cluster_app.command("show")
def cluster_show(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
) -> None:
    """Members, relations, evidence, and event history for one campaign."""
    with session_scope() as session:
        campaign = session.scalar(select(Campaign).where(Campaign.code == campaign_id))
        if campaign is None:
            raise typer.BadParameter(f"No campaign with code {campaign_id!r}")

        members = list(
            session.scalars(select(CampaignMember).where(CampaignMember.campaign_id == campaign.id))
        )
        member_ids = {m.indicator_id for m in members}
        indicators_by_id = {
            i.id: i for i in session.scalars(select(Indicator).where(Indicator.id.in_(member_ids)))
        }

        console.print(
            f"[bold]{campaign.code}[/bold] ({campaign.display_name or 'unnamed'}) — "
            f"{campaign.status}, score={campaign.score:.2f}"
        )
        console.print(f"Relations: {', '.join(campaign.relation_types)}")
        console.print(
            f"First seen: {campaign.first_seen.isoformat()} | "
            f"Last seen: {campaign.last_seen.isoformat()}"
        )

        member_table = Table(title="Members")
        member_table.add_column("Type")
        member_table.add_column("Value")
        member_table.add_column("Joined")
        for member in sorted(members, key=lambda m: str(m.indicator_id)):
            indicator = indicators_by_id.get(member.indicator_id)
            if indicator is None:
                continue
            member_table.add_row(
                indicator.type.value, indicator.value, member.joined_at.isoformat()
            )
        console.print(member_table)

        edges = list(
            session.scalars(
                select(Edge).where(
                    Edge.src_indicator_id.in_(member_ids), Edge.dst_indicator_id.in_(member_ids)
                )
            )
        )
        edge_table = Table(title="Edges / evidence")
        edge_table.add_column("Src")
        edge_table.add_column("Dst")
        edge_table.add_column("Relation")
        edge_table.add_column("Weight", justify="right")
        edge_table.add_column("Evidence")
        for edge in sorted(edges, key=_edge_sort_key):
            src = indicators_by_id.get(edge.src_indicator_id)
            dst = indicators_by_id.get(edge.dst_indicator_id)
            edge_table.add_row(
                src.value if src else str(edge.src_indicator_id),
                dst.value if dst else str(edge.dst_indicator_id),
                edge.relation.value,
                f"{edge.weight:.2f}",
                json.dumps(edge.evidence, default=str),
            )
        console.print(edge_table)

        events = list(
            session.scalars(
                select(CampaignEvent)
                .where(CampaignEvent.campaign_id == campaign.id)
                .order_by(CampaignEvent.occurred_at)
            )
        )
        if events:
            event_table = Table(title="Event history")
            event_table.add_column("Type")
            event_table.add_column("Occurred at")
            event_table.add_column("Related codes")
            for event in events:
                event_table.add_row(
                    event.event_type,
                    event.occurred_at.isoformat(),
                    ", ".join(event.related_campaign_codes),
                )
            console.print(event_table)


@cluster_app.command("explain")
def cluster_explain(
    indicator_value: str = typer.Argument(..., help="Indicator value (address, domain, etc.)."),
) -> None:
    """Why this indicator is in its campaign: its direct edges/evidence,
    plus the path to the campaign's lowest-id member for context on
    larger campaigns."""
    with session_scope() as session:
        indicator = session.scalar(select(Indicator).where(Indicator.value == indicator_value))
        if indicator is None:
            raise typer.BadParameter(f"No indicator with value {indicator_value!r}")

        member = session.scalar(
            select(CampaignMember).where(CampaignMember.indicator_id == indicator.id)
        )
        if member is None:
            console.print(f"[yellow]{indicator_value!r} is not a member of any campaign.[/yellow]")
            raise typer.Exit()

        campaign = session.scalar(select(Campaign).where(Campaign.id == member.campaign_id))
        assert campaign is not None
        console.print(
            f"[bold]{indicator_value}[/bold] is a member of [bold]{campaign.code}[/bold] "
            f"({campaign.status}, score={campaign.score:.2f})"
        )

        result = explain_indicator(session, indicator.id, campaign.id)
        indicators_by_id = {
            i.id: i
            for i in session.scalars(select(Indicator).where(Indicator.id.in_(result.member_ids)))
        }

        direct_table = Table(title=f"Direct edges for {indicator_value}")
        direct_table.add_column("Neighbor")
        direct_table.add_column("Relation")
        direct_table.add_column("Weight", justify="right")
        direct_table.add_column("Evidence")
        for edge in result.direct_edges:
            neighbor = indicators_by_id.get(edge.neighbor_id)
            direct_table.add_row(
                neighbor.value if neighbor else str(edge.neighbor_id),
                edge.relation,
                f"{edge.weight:.2f}",
                json.dumps(edge.evidence, default=str),
            )
        console.print(direct_table)

        if result.path_to_reference:
            path_values = [
                indicators_by_id[node_id].value if node_id in indicators_by_id else str(node_id)
                for node_id in result.path_to_reference
            ]
            console.print(f"Path to campaign reference member: {' -> '.join(path_values)}")


@cluster_app.command("graph")
def cluster_graph_cmd(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    output_format: str = typer.Option("json", "--format", help="Output format: json or dot."),
) -> None:
    """Export a campaign's member/edge graph."""
    if output_format not in ("json", "dot"):
        raise typer.BadParameter("--format must be 'json' or 'dot'")

    with session_scope() as session:
        campaign = session.scalar(select(Campaign).where(Campaign.code == campaign_id))
        if campaign is None:
            raise typer.BadParameter(f"No campaign with code {campaign_id!r}")

        member_ids = [
            m.indicator_id
            for m in session.scalars(
                select(CampaignMember).where(CampaignMember.campaign_id == campaign.id)
            )
        ]
        indicators_by_id = {
            i.id: i for i in session.scalars(select(Indicator).where(Indicator.id.in_(member_ids)))
        }
        edges = list(
            session.scalars(
                select(Edge).where(
                    Edge.src_indicator_id.in_(member_ids), Edge.dst_indicator_id.in_(member_ids)
                )
            )
        )

        if output_format == "json":
            payload = {
                "campaign": campaign.code,
                "nodes": [
                    {"id": str(node_id), "type": ind.type.value, "value": ind.value}
                    for node_id, ind in sorted(indicators_by_id.items(), key=lambda kv: str(kv[0]))
                ],
                "edges": [
                    {
                        "src": str(edge.src_indicator_id),
                        "dst": str(edge.dst_indicator_id),
                        "relation": edge.relation.value,
                        "weight": edge.weight,
                        "evidence": edge.evidence,
                    }
                    for edge in sorted(
                        edges,
                        key=_edge_sort_key,
                    )
                ],
            }
            # Plain print, not console.print — see the same note on `lh
            # trace --format json`: this is for piping, not a terminal.
            print(json.dumps(payload, indent=2, default=str))
        else:
            lines = [f"graph {campaign.code.replace('-', '_')} {{"]
            for node_id, ind in sorted(indicators_by_id.items(), key=lambda kv: str(kv[0])):
                label = ind.value if len(ind.value) <= 24 else ind.value[:22] + "…"
                lines.append(f'  "{node_id}" [label="{label}"];')
            for edge in sorted(
                edges,
                key=_edge_sort_key,
            ):
                lines.append(
                    f'  "{edge.src_indicator_id}" -- "{edge.dst_indicator_id}" '
                    f'[label="{edge.relation.value}"];'
                )
            lines.append("}")
            print("\n".join(lines))


def _get_campaign(session: Session, code: str) -> Campaign:
    campaign = session.scalar(select(Campaign).where(Campaign.code == code))
    if campaign is None:
        raise typer.BadParameter(f"No campaign with code {code!r}")
    return campaign


@assess_app.command("draft")
def assess_draft(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    force: bool = typer.Option(
        False, "--force", help="Redraft even if evidence hasn't changed since the last version."
    ),
) -> None:
    """Build the evidence pack, call the LLM, validate, and store a new draft version."""
    settings = get_settings()
    attack_dataset = load_attack_dataset(settings.attack_stix_cache_path)

    with session_scope() as session:
        runtime_config = config_store.get_runtime_config(session)
        if not runtime_config.llm_api_key:
            raise typer.BadParameter(
                "llm_api_key is not set (required only for `lh assess draft`)."
            )
        llm = OpenAICompatibleLLM(
            api_key=runtime_config.llm_api_key, base_url=runtime_config.llm_base_url
        )

        campaign = _get_campaign(session, campaign_id)
        try:
            assessment = draft_assessment(
                session,
                campaign,
                llm=llm,
                model=runtime_config.llm_model,
                attack_dataset=attack_dataset,
                force=force,
            )
        except DraftBlockedError as exc:
            err_console.print(f"[yellow]{exc}[/yellow]")
            raise typer.Exit(1) from exc
        except DraftValidationError as exc:
            err_console.print("[red]Draft rejected by validation:[/red]")
            for error in exc.errors:
                err_console.print(f"  - {error}")
            raise typer.Exit(1) from exc
        version = assessment.version

    console.print(f"[green]{campaign_id}: drafted version {version}.[/green]")


@assess_app.command("show")
def assess_show(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    version: int | None = typer.Option(
        None, "--version", help="Show this version. Default: latest."
    ),
) -> None:
    """Render a draft with its evidence refs expanded inline."""
    with session_scope() as session:
        campaign = _get_campaign(session, campaign_id)
        try:
            assessment = get_version(session, campaign.id, version)
        except LookupError as exc:
            raise typer.BadParameter(str(exc)) from exc

        pack = build_evidence_pack(session, campaign)
        ref_descriptions = describe_refs(pack)
        draft = assessment.draft

        stale_tag = "[yellow](stale)[/yellow] " if assessment.stale else ""
        console.print(
            f"[bold]{campaign_id}[/bold] v{assessment.version} — status={assessment.status} "
            f"{stale_tag}model={assessment.model} prompt={assessment.prompt_version} "
            f"edited_by_human={assessment.edited_by_human}"
        )
        console.print(f"[bold]Summary:[/bold] {draft['summary']}")

        judgement_table = Table(title="Key judgements")
        judgement_table.add_column("Confidence")
        judgement_table.add_column("Statement")
        judgement_table.add_column("Evidence")
        for judgement in draft["key_judgements"]:
            refs = judgement.get("supporting_evidence_refs", [])
            expanded = "\n".join(
                ref_descriptions.get(ref, f"{ref} (evidence unavailable)") for ref in refs
            )
            judgement_table.add_row(
                judgement["confidence"], judgement["statement"], expanded or "-"
            )
        console.print(judgement_table)

        targeting = draft["targeting"]
        console.print(
            f"[bold]Targeting:[/bold] {targeting['victim_profile']} | "
            f"Geographies: {', '.join(targeting.get('geographies', [])) or '-'} | "
            f"Impersonated brands: {', '.join(targeting.get('impersonated_brands', [])) or '-'}"
        )

        ttp_table = Table(title="TTPs (MITRE ATT&CK)")
        ttp_table.add_column("Technique")
        ttp_table.add_column("Name")
        ttp_table.add_column("Observation")
        for ttp in draft["ttps"]:
            ttp_table.add_row(ttp["technique_id"], ttp["technique_name"], ttp["observation"])
        console.print(ttp_table)

        financial = draft["financial"]
        console.print(
            f"[bold]Financial:[/bold] {financial['narrative']}\n"
            f"Total observed inflow: {financial['total_observed_inflow']} | "
            f"Cashout venues: {', '.join(financial.get('cashout_venues', [])) or '-'} | "
            f"Sanctions exposure: {financial['sanctions_exposure']}"
        )
        console.print(f"[bold]Assessment:[/bold] {draft['assessment']}")

        attribution = draft["attribution"]
        console.print(
            f"[bold]Attribution:[/bold] claim={attribution['claim'] or '(none — unattributed)'} "
            f"confidence={attribution['confidence'] or '-'}\nRationale: {attribution['rationale']}"
        )
        console.print(f"[bold]Outlook:[/bold] {draft['outlook']}")

        if draft.get("gaps"):
            console.print("[bold]Gaps:[/bold]")
            for gap in draft["gaps"]:
                console.print(f"  - {gap}")

        if assessment.reviewed_by:
            reviewed_at = assessment.reviewed_at.isoformat() if assessment.reviewed_at else "-"
            console.print(
                f"Reviewed by {assessment.reviewed_by} at {reviewed_at}: "
                f"{assessment.reviewer_notes or '-'}"
            )


@assess_app.command("edit")
def assess_edit(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    version: int | None = typer.Option(
        None, "--version", help="Edit this version. Default: latest."
    ),
) -> None:
    """Open a version's draft JSON in $EDITOR; on save, re-validate and store as a new version."""
    settings = get_settings()
    attack_dataset = load_attack_dataset(settings.attack_stix_cache_path)

    with session_scope() as session:
        campaign = _get_campaign(session, campaign_id)
        try:
            source = get_version(session, campaign.id, version)
        except LookupError as exc:
            raise typer.BadParameter(str(exc)) from exc

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(source.draft, handle, indent=2, sort_keys=True)
            tmp_path = Path(handle.name)

        try:
            editor = os.environ.get("EDITOR", "vi")
            subprocess.run([editor, str(tmp_path)], check=True)

            try:
                edited_raw = json.loads(tmp_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                err_console.print(f"[red]Edited file is not valid JSON: {exc}[/red]")
                raise typer.Exit(1) from exc

            try:
                new_assessment = edit_assessment(
                    session, campaign, source, edited_raw, attack_dataset=attack_dataset
                )
            except DraftValidationError as exc:
                err_console.print("[red]Edited draft rejected by validation:[/red]")
                for error in exc.errors:
                    err_console.print(f"  - {error}")
                raise typer.Exit(1) from exc
        finally:
            tmp_path.unlink(missing_ok=True)

        new_version = new_assessment.version

    console.print(f"[green]{campaign_id}: stored version {new_version} (edited).[/green]")


@assess_app.command("approve")
def assess_approve(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    version: int | None = typer.Option(
        None, "--version", help="Approve this version. Default: latest."
    ),
    notes: str = typer.Option(..., "--notes", help="Review notes explaining the approval."),
    reviewer: str | None = typer.Option(
        None, "--reviewer", help="Defaults to the local OS username."
    ),
    force: bool = typer.Option(
        False, "--force", help="Supersede an already-approved version for this campaign."
    ),
) -> None:
    """Approve a version. Exactly one approved version can exist per campaign."""
    reviewer_name = reviewer or getpass.getuser()
    with session_scope() as session:
        campaign = _get_campaign(session, campaign_id)
        try:
            assessment = approve_assessment(
                session,
                campaign,
                version=version,
                reviewer=reviewer_name,
                notes=notes,
                force=force,
            )
        except LookupError as exc:
            raise typer.BadParameter(str(exc)) from exc
        except IllegalTransitionError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        except AlreadyApprovedError as exc:
            err_console.print(f"[yellow]{exc}[/yellow]")
            raise typer.Exit(1) from exc
        result_version = assessment.version

    console.print(f"[green]{campaign_id}: version {result_version} approved.[/green]")


@assess_app.command("reject")
def assess_reject(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    version: int | None = typer.Option(
        None, "--version", help="Reject this version. Default: latest."
    ),
    notes: str = typer.Option(..., "--notes", help="Review notes explaining the rejection."),
    reviewer: str | None = typer.Option(
        None, "--reviewer", help="Defaults to the local OS username."
    ),
) -> None:
    """Reject a version."""
    reviewer_name = reviewer or getpass.getuser()
    with session_scope() as session:
        campaign = _get_campaign(session, campaign_id)
        try:
            assessment = reject_assessment(
                session, campaign, version=version, reviewer=reviewer_name, notes=notes
            )
        except LookupError as exc:
            raise typer.BadParameter(str(exc)) from exc
        except IllegalTransitionError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        result_version = assessment.version

    console.print(f"[green]{campaign_id}: version {result_version} rejected.[/green]")


@assess_app.command("diff")
def assess_diff(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    version_a: int = typer.Argument(..., help="First version."),
    version_b: int = typer.Argument(..., help="Second version."),
) -> None:
    """Unified diff between two draft versions' JSON."""
    with session_scope() as session:
        campaign = _get_campaign(session, campaign_id)
        try:
            assessment_a = get_version(session, campaign.id, version_a)
            assessment_b = get_version(session, campaign.id, version_b)
        except LookupError as exc:
            raise typer.BadParameter(str(exc)) from exc
        diff_text = render_diff(assessment_a, assessment_b)

    # Plain print, not console.print — see the same note on `lh trace
    # --format json`: a diff is for reading/piping, not rich styling.
    print(diff_text or "(no differences)")


@export_app.command("stix")
def export_stix(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    out: Path | None = typer.Option(
        None, "--out", help="Output file path. Default: <export_output_path>/stix/<CODE>.json"
    ),
) -> None:
    """Export one campaign's approved, non-stale assessment as a STIX 2.1 bundle."""
    settings = get_settings()
    try:
        attack_dataset = load_cached_attack_dataset(settings.attack_stix_cache_path)
    except AttackDatasetUnavailableError as exc:
        raise typer.BadParameter(str(exc)) from exc

    with session_scope() as session:
        tlp = config_store.get_runtime_config(session).tlp_default
        campaign = _get_campaign(session, campaign_id)
        try:
            assessment, pack = get_publishable_assessment(session, campaign)
        except NotPublishableError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        try:
            bundle = build_campaign_bundle(
                campaign, assessment, pack, attack_dataset=attack_dataset, tlp=tlp
            )
        except StixExportError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc

    bundle_bytes = serialize_bundle(bundle)
    out_path = out or (settings.export_output_path / "stix" / f"{campaign_id}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bundle_bytes)
    console.print(f"[green]Wrote {out_path}[/green]")


@export_app.command("misp")
def export_misp_cmd(
    out: Path | None = typer.Option(
        None, "--out", help="Output directory. Default: <export_output_path>/misp"
    ),
) -> None:
    """Write the MISP feed for every currently-publishable campaign."""
    settings = get_settings()
    out_dir = out or (settings.export_output_path / "misp")
    with session_scope() as session:
        tlp = config_store.get_runtime_config(session).tlp_default
        campaigns = list_publishable_campaigns(session)
        if not campaigns:
            console.print("[yellow]No publishable campaigns.[/yellow]")
            raise typer.Exit()
        written = write_misp_feed(out_dir, campaigns, tlp=tlp)
    console.print(
        f"[green]Wrote {len(written)} files to {out_dir} ({len(campaigns)} campaigns).[/green]"
    )


@export_app.command("feed")
def export_feed_cmd(
    out: Path | None = typer.Option(
        None, "--out", help="Output directory. Default: <export_output_path>/feed"
    ),
    refanged: bool = typer.Option(
        False, "--refanged", help="Emit raw (non-defanged) indicator values."
    ),
) -> None:
    """Write the static IOC feed for every currently-publishable campaign."""
    settings = get_settings()
    out_dir = out or (settings.export_output_path / "feed")
    with session_scope() as session:
        campaigns = list_publishable_campaigns(session)
        if not campaigns:
            console.print("[yellow]No publishable campaigns.[/yellow]")
            raise typer.Exit()
        written = write_feed(out_dir, campaigns, refanged=refanged)
    console.print(
        f"[green]Wrote {len(written)} files to {out_dir} ({len(campaigns)} campaigns).[/green]"
    )


@report_app.command("render")
def report_render(
    campaign_id: str = typer.Argument(..., help="Campaign code, e.g. LH-2026-001."),
    output_format: str = typer.Option("both", "--format", help="md, pdf, or both."),
    out: Path | None = typer.Option(
        None, "--out", help="Output directory. Default: <reports_path>/<CODE>/"
    ),
) -> None:
    """Render an approved, non-stale campaign assessment to Markdown and/or PDF."""
    if output_format not in ("md", "pdf", "both"):
        raise typer.BadParameter("--format must be one of: md, pdf, both")
    settings = get_settings()
    out_dir = out or (settings.reports_path / campaign_id)

    with session_scope() as session:
        tlp = config_store.get_runtime_config(session).tlp_default
        campaign = _get_campaign(session, campaign_id)
        try:
            assessment, pack = get_publishable_assessment(session, campaign)
        except NotPublishableError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        context, graph_png = build_report_context(
            campaign,
            assessment,
            pack,
            tlp=tlp,
            stix_bundle_filename=f"{campaign_id}.json",
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    graph_png_filename = context["graph_png_filename"]
    if graph_png is not None and graph_png_filename:
        (out_dir / graph_png_filename).write_bytes(graph_png)

    markdown_text = render_markdown(context)
    if output_format in ("md", "both"):
        (out_dir / "report.md").write_text(markdown_text, encoding="utf-8")
        console.print(f"[green]Wrote {out_dir / 'report.md'}[/green]")
    if output_format in ("pdf", "both"):
        try:
            pdf_bytes = render_pdf(markdown_text, base_url=str(out_dir))
        except ReportRenderError as exc:
            err_console.print(f"[yellow]{exc}[/yellow]")
            if output_format == "pdf":
                raise typer.Exit(1) from exc
        else:
            (out_dir / "report.pdf").write_bytes(pdf_bytes)
            console.print(f"[green]Wrote {out_dir / 'report.pdf'}[/green]")


@app.command("publish")
def publish(
    campaign_id: str | None = typer.Argument(
        None, help="Campaign code, e.g. LH-2026-001. Omit with --all."
    ),
    publish_all: bool = typer.Option(
        False, "--all", help="Publish every currently-publishable campaign."
    ),
) -> None:
    """Export STIX, regenerate the MISP/IOC feeds, and render the report
    for one campaign (or every publishable campaign with --all), then
    record a `publications` row with every artifact's hash. Refuses a
    campaign whose assessment isn't approved or has gone stale."""
    if bool(campaign_id) == publish_all:
        raise typer.BadParameter("Specify exactly one of CAMPAIGN_ID or --all.")

    settings = get_settings()
    try:
        attack_dataset = load_cached_attack_dataset(settings.attack_stix_cache_path)
    except AttackDatasetUnavailableError as exc:
        raise typer.BadParameter(str(exc)) from exc

    with session_scope() as session:
        tlp = config_store.get_runtime_config(session).tlp_default
        if publish_all:
            targets = list_publishable_campaigns(session)
            if not targets:
                console.print("[yellow]No publishable campaigns.[/yellow]")
                raise typer.Exit()
        else:
            assert campaign_id is not None
            campaign = _get_campaign(session, campaign_id)
            try:
                assessment, pack = get_publishable_assessment(session, campaign)
            except NotPublishableError as exc:
                err_console.print(f"[red]{exc}[/red]")
                raise typer.Exit(1) from exc
            targets = [(campaign, assessment, pack)]

        # The MISP feed and IOC feed are collection-level artifacts (a
        # manifest describing every event/campaign in the directory), so
        # every publish regenerates them across every currently-
        # publishable campaign, not just the one(s) being published here.
        all_publishable = targets if publish_all else list_publishable_campaigns(session)
        misp_dir = settings.export_output_path / "misp"
        write_misp_feed(misp_dir, all_publishable, tlp=tlp)
        feed_dir = settings.export_output_path / "feed"
        write_feed(feed_dir, all_publishable, refanged=False)

        published_codes: list[str] = []
        for campaign, assessment, pack in targets:
            try:
                bundle = build_campaign_bundle(
                    campaign,
                    assessment,
                    pack,
                    attack_dataset=attack_dataset,
                    tlp=tlp,
                )
            except StixExportError as exc:
                err_console.print(f"[red]{campaign.code}: {exc}[/red]")
                continue

            bundle_bytes = serialize_bundle(bundle)
            stix_path = settings.export_output_path / "stix" / f"{campaign.code}.json"
            stix_path.parent.mkdir(parents=True, exist_ok=True)
            stix_path.write_bytes(bundle_bytes)

            report_dir = settings.reports_path / campaign.code
            report_dir.mkdir(parents=True, exist_ok=True)
            context, graph_png = build_report_context(
                campaign,
                assessment,
                pack,
                tlp=tlp,
                stix_bundle_filename=Path(
                    os.path.relpath(stix_path, start=report_dir)
                ).as_posix(),
            )
            graph_png_filename = context["graph_png_filename"]
            if graph_png is not None and graph_png_filename:
                (report_dir / graph_png_filename).write_bytes(graph_png)

            markdown_text = render_markdown(context)
            report_md_path = report_dir / "report.md"
            report_md_path.write_text(markdown_text, encoding="utf-8")

            artifacts: dict[str, Any] = {
                "stix_bundle": {
                    "path": str(stix_path),
                    "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
                },
                "report_md": {
                    "path": str(report_md_path),
                    "sha256": hashlib.sha256(markdown_text.encode("utf-8")).hexdigest(),
                },
            }
            try:
                pdf_bytes = render_pdf(markdown_text, base_url=str(report_dir))
            except ReportRenderError as exc:
                err_console.print(f"[yellow]{campaign.code}: {exc}[/yellow]")
            else:
                report_pdf_path = report_dir / "report.pdf"
                report_pdf_path.write_bytes(pdf_bytes)
                artifacts["report_pdf"] = {
                    "path": str(report_pdf_path),
                    "sha256": hashlib.sha256(pdf_bytes).hexdigest(),
                }

            misp_event = build_misp_event(campaign, assessment, pack, tlp=tlp)
            misp_event_bytes = serialize_event(misp_event)
            artifacts["misp_event"] = {
                "path": str(misp_dir / f"{misp_event['Event']['uuid']}.json"),
                "sha256": hashlib.sha256(misp_event_bytes).hexdigest(),
            }

            feed_entry = build_campaign_entry(campaign, assessment, pack, refanged=False)
            feed_entry_bytes = (json.dumps(feed_entry, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
            artifacts["feed_campaign"] = {
                "path": str(feed_dir / f"{campaign.code}.json"),
                "sha256": hashlib.sha256(feed_entry_bytes).hexdigest(),
            }

            session.add(
                Publication(
                    campaign_id=campaign.id,
                    assessment_id=assessment.id,
                    published_at=datetime.now(UTC),
                    tlp=tlp,
                    artifacts=artifacts,
                )
            )
            published_codes.append(campaign.code)

    if published_codes:
        console.print(f"[green]Published: {', '.join(published_codes)}[/green]")
    else:
        console.print("[yellow]Nothing was published.[/yellow]")


def _check_domain(domain: str) -> config_store.Domain:
    if domain not in config_store.DOMAINS:
        raise typer.BadParameter(f"Unknown domain {domain!r}. Valid: {list(config_store.DOMAINS)}")
    return domain


@config_app.command("show")
def config_show(
    domain: str | None = typer.Argument(
        None, help="One of: sources, providers, clustering, runtime. Omit to show all."
    ),
) -> None:
    """Show a config domain's effective value (its override, if one has
    been set via `lh config set` or the dashboard's Settings page —
    otherwise its file/env default) and which one it's using."""
    domains = [_check_domain(domain)] if domain else list(config_store.DOMAINS)
    with session_scope() as session:
        for d in domains:
            value = config_store.get_config(session, d)
            source = "override" if config_store.is_overridden(session, d) else "file/env default"
            console.print(f"[bold]{d}[/bold] ([dim]{source}[/dim]):")
            console.print_json(data=value.model_dump(mode="json"))


@config_app.command("set")
def config_set(
    domain: str = typer.Argument(..., help="One of: sources, providers, clustering, runtime."),
    key: str | None = typer.Argument(
        None, help="Field to set (runtime domain only, e.g. llm_model). Omit with --json/--file."
    ),
    value: str | None = typer.Argument(None, help="New value for KEY (runtime domain only)."),
    json_value: str | None = typer.Option(
        None, "--json", help="Replace the whole domain with this JSON document."
    ),
    file: Path | None = typer.Option(
        None, "--file", help="Replace the whole domain with this JSON file's contents."
    ),
) -> None:
    """Edit a config domain, taking effect immediately (no restart).

    `runtime` supports one field at a time: `lh config set runtime
    llm_model gpt-4o`. `sources`/`providers`/`clustering` are structured
    documents — replace the whole thing with `--json`/`--file` (fetch the
    current value from `lh config show DOMAIN` to edit and resubmit), or
    use the dashboard's Settings page, which edits this exact same store.
    """
    checked_domain = _check_domain(domain)

    with session_scope() as session:
        if json_value is not None or file is not None:
            if key is not None or value is not None:
                raise typer.BadParameter("Don't combine KEY/VALUE with --json/--file.")
            raw_text = file.read_text(encoding="utf-8") if file is not None else json_value
            assert raw_text is not None
            raw = json.loads(raw_text)
        else:
            if checked_domain != "runtime":
                raise typer.BadParameter(
                    f"{domain!r} is a structured document — use --json or --file to replace it "
                    "(or edit it from the dashboard's Settings page)."
                )
            if key is None or value is None:
                raise typer.BadParameter("Specify KEY and VALUE, or --json/--file.")
            raw = config_store.get_runtime_config(session).model_dump(mode="json")
            if key not in raw:
                raise typer.BadParameter(f"Unknown runtime key {key!r}. Valid: {sorted(raw)}")
            # yaml.safe_load on a single scalar gives real types (int,
            # float, bool, null) instead of everything staying a string.
            raw[key] = yaml.safe_load(value)

        try:
            validated = config_store.set_config(
                session, checked_domain, raw, updated_by=getpass.getuser()
            )
        except config_store.ConfigValidationError as exc:
            err_console.print("[red]Rejected:[/red]")
            for error in exc.errors:
                err_console.print(f"  - {error}")
            raise typer.Exit(1) from exc

    console.print(f"[green]{domain} updated.[/green]")
    console.print_json(data=validated.model_dump(mode="json"))


@config_app.command("reset")
def config_reset(
    domain: str = typer.Argument(..., help="One of: sources, providers, clustering, runtime."),
) -> None:
    """Delete DOMAIN's override, reverting to its file/env default."""
    checked_domain = _check_domain(domain)
    with session_scope() as session:
        config_store.reset_config(session, checked_domain)
    console.print(f"[green]{domain} reverted to its file/env default.[/green]")


@app.command("serve")
def serve(
    port: int = typer.Option(8000, "--port", help="Port to listen on."),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to."),
    reload: bool = typer.Option(
        False,
        "--reload",
        help="Auto-reload on code changes (dev; pair with `npm run dev` in web/).",
    ),
) -> None:
    """Run the dashboard's FastAPI app.

    If `web/dist/` exists (from `npm run build`), it's served from this
    same process at `/` and the dashboard is a single process. In dev,
    run `npm run dev` in `web/` alongside `lh serve --reload` instead —
    Vite's dev server proxies API requests here (see web/vite.config.ts).
    """
    import uvicorn

    uvicorn.run("ledgerhound.api.main:app", host=host, port=port, reload=reload)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
