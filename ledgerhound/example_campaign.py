"""Build the sanitised LH-2026-001 example from local fixtures.

The run uses the real extraction, clustering, assessment, and export code.
Collection is an in-process replay of ``examples/fixtures/lh-2026-001.json``.
Chain totals are fixture numbers written straight onto the projection
tables. Nothing in this module opens a socket to a feed, a registry, or a
chain. Time and row ids are pinned so a second run matches the first.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from freezegun import freeze_time
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.schema import ColumnDefault

from ledgerhound import __author__ as PRODUCT_AUTHOR
from ledgerhound.assess.attack import AttackDataset
from ledgerhound.assess.drafter import draft_assessment
from ledgerhound.assess.evidence import build_evidence_pack
from ledgerhound.assess.review import approve_assessment
from ledgerhound.cluster.campaigns import run_clustering
from ledgerhound.cluster.config import load_clustering_config
from ledgerhound.collect.base import Collector
from ledgerhound.db.models import (
    AddressCounterparty,
    AddressProfile,
    Assessment,
    Base,
    Campaign,
    Indicator,
    IndicatorType,
    RawReport,
    Source,
    SourceType,
)
from ledgerhound.export.feed import write_feed
from ledgerhound.export.misp import build_misp_event, serialize_event, write_misp_feed
from ledgerhound.export.report import build_report_context, render_markdown, render_pdf
from ledgerhound.export.stix import build_campaign_bundle, serialize_bundle
from ledgerhound.extract.normalize import to_eip55
from ledgerhound.extract.pipeline import run_extraction
from ledgerhound.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "examples" / "fixtures" / "lh-2026-001.json"
FROZEN_AT = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
CAMPAIGN_CODE = "LH-2026-001"
EMPTY_ATTACK = AttackDataset(version="fixture", techniques={}, stix_ids={})

_FOLDER_README = """\
# LH-2026-001

SANITISED EXAMPLE. This folder is synthetic output from
`make example`. Domains are under `.example`. Addresses are patterned
test values. Chain totals were written from the fixture, not looked up.
Do not treat any indicator here as a real compromise.
"""


class _FixtureCollector(Collector):
    """Replays a list of records. No HTTP."""

    name = "sanitised-example"

    def __init__(self, records: list[dict[str, Any]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._records = records

    def fetch(self) -> Iterable[dict[str, Any]]:
        return iter(self._records)

    def content_hash(self, record: dict[str, Any]) -> str:
        return self.stable_hash(record)


class _SeqUUID:
    def __init__(self) -> None:
        self._n = 0

    def __call__(self, *_args: Any, **_kwargs: Any) -> uuid.UUID:
        self._n += 1
        return uuid.UUID(int=self._n)


class _FixtureLLM:
    """Deterministic stand-in for the assessment model. Reads the inflow
    figure the prompt already computed and fills the schema. No network."""

    def draft(
        self,
        *,
        model: str,
        system: str,
        user_message: str,
        tool_schema: dict[str, Any],
    ) -> dict[str, Any]:
        del model, system, tool_schema
        match = re.search(r"total_observed_inflow is exactly: '([^']+)'", user_message)
        if match is None:
            raise RuntimeError("example drafter could not read total_observed_inflow")
        inflow = match.group(1)
        return {
            "key_judgements": [
                {
                    "statement": (
                        "SANITISED EXAMPLE. Three synthetic addresses show outbound "
                        "transfers to the same fixture wallet in the local enrichment rows."
                    ),
                    "confidence": "moderate",
                    "supporting_evidence_refs": [],
                }
            ],
            "summary": (
                "SANITISED EXAMPLE. This campaign is a portfolio fixture, not a "
                "real cluster. The lures use wallet-support.example, claim-drop.example, "
                "and restore-login.example."
            ),
            "targeting": {
                "victim_profile": "No victims. The narrative is a sanitised fixture.",
                "geographies": [],
                "impersonated_brands": ["Example Wallet"],
            },
            "ttps": [],
            "financial": {
                "narrative": (
                    "Inflow figures are the fixture totals, summed by the evidence pack. "
                    "They were not read from a chain."
                ),
                "total_observed_inflow": inflow,
                "cashout_venues": [],
                "sanctions_exposure": "None in this fixture.",
            },
            "assessment": (
                "SANITISED EXAMPLE. The addresses are linked only because the fixture "
                "gave them the same outbound counterparty."
            ),
            "attribution": {
                "claim": None,
                "confidence": None,
                "rationale": "Synthetic data. No attribution.",
            },
            "outlook": "This fixture does not describe a live operation.",
            "gaps": [
                "No live enrichment was performed.",
                "ATT&CK techniques were left empty so the bundle would not invent a MITRE id.",
            ],
        }


def _swap_uuid_defaults(seq: _SeqUUID) -> list[tuple[Any, ColumnDefault, Any]]:
    """SQLAlchemy wraps ``uuid.uuid4`` in a per-column callable, so identity
    with ``uuid.uuid4`` does not hold. Match on the wrapper's name.

    The callable is also memoized on the column the first time a row is
    inserted. Drop that cache so this run actually calls `seq`, and drop
    it again on restore so later work goes back to ``uuid4``.
    """
    saved: list[tuple[Any, ColumnDefault, Any]] = []
    for table in Base.metadata.tables.values():
        for column in table.columns:
            default = column.default
            if not isinstance(default, ColumnDefault) or not default.is_callable:
                continue
            if getattr(default.arg, "__name__", None) != "uuid4":
                continue
            saved.append((column, default, default.arg))
            default.arg = seq
            column.__dict__.pop("_default_description_tuple", None)
    if not saved:
        raise RuntimeError("could not pin UUID defaults; example output would not be stable")
    return saved


def _restore_uuid_defaults(saved: list[tuple[Any, ColumnDefault, Any]]) -> None:
    for column, default, original in saved:
        default.arg = original
        column.__dict__.pop("_default_description_tuple", None)


def _load_fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return loaded


def _open_session(db_path: Path) -> tuple[Session, Any]:
    engine = create_engine(
        f"sqlite+pysqlite:///{db_path}",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    return factory(), engine


def _populate(session: Session, fixture: dict[str, Any]) -> Campaign:
    settings = Settings(_env_file=None)
    source = Source(
        name="sanitised-example",
        type=SourceType.PHISHING_FEED,
        url="https://example.invalid/sanitised-fixture",
        cadence_minutes=60,
        reliability_grade="C",
        enabled=True,
    )
    session.add(source)
    session.flush()

    records = [
        {"label": fixture["label"], "text": report["text"]}
        for report in fixture["reports"]
    ]
    _FixtureCollector(records, settings=settings).run(session, source)

    reports = session.scalars(select(RawReport).order_by(RawReport.content_hash)).all()
    for index, report in enumerate(reports):
        report.fetched_at = FROZEN_AT + timedelta(seconds=index)
    session.commit()

    run_extraction(session)

    wallet = str(fixture["shared_outbound_wallet"])
    enriched_at = FROZEN_AT
    for report in fixture["reports"]:
        canonical = to_eip55(str(report["address"]))
        indicator = session.scalar(
            select(Indicator).where(
                Indicator.type == IndicatorType.ETH_ADDRESS,
                Indicator.value == canonical,
            )
        )
        if indicator is None:
            raise RuntimeError(f"extraction missed synthetic address {canonical}")
        session.add(
            AddressProfile(
                indicator_id=indicator.id,
                chain="eth",
                tx_count=1,
                total_received=Decimal(str(report["total_received"])),
                total_sent=Decimal(0),
                current_balance=Decimal(0),
                decimals=18,
                provider="sanitised-fixture",
                enriched_at=enriched_at,
            )
        )
        session.add(
            AddressCounterparty(
                indicator_id=indicator.id,
                counterparty_address=wallet,
                direction="out",
                tx_count=1,
                total_value=Decimal(str(report["total_received"])),
            )
        )
    session.flush()

    config = load_clustering_config(REPO_ROOT / "config" / "clustering.yaml")
    run_clustering(session, config)
    campaign = session.scalar(select(Campaign).where(Campaign.code == CAMPAIGN_CODE))
    if campaign is None:
        codes = list(session.scalars(select(Campaign.code)))
        raise RuntimeError(f"expected {CAMPAIGN_CODE}, found {codes}")
    campaign.display_name = "SANITISED EXAMPLE"
    session.commit()

    draft_assessment(
        session,
        campaign,
        llm=_FixtureLLM(),
        model="sanitised-fixture",
        attack_dataset=EMPTY_ATTACK,
    )
    session.commit()
    approve_assessment(
        session,
        campaign,
        version=1,
        reviewer=PRODUCT_AUTHOR,
        notes="SANITISED EXAMPLE approved for the offline portfolio build.",
    )
    session.commit()
    return campaign


def _write_artifacts(session: Session, campaign: Campaign, out_dir: Path) -> None:
    assessment = session.scalar(
        select(Assessment).where(
            Assessment.campaign_id == campaign.id,
            Assessment.status == "approved",
        )
    )
    if assessment is None:
        raise RuntimeError("example campaign has no approved assessment")
    pack = build_evidence_pack(session, campaign)
    bundle = build_campaign_bundle(
        campaign,
        assessment,
        pack,
        attack_dataset=EMPTY_ATTACK,
        tlp="TLP:CLEAR",
    )
    (out_dir / "stix-bundle.json").write_bytes(serialize_bundle(bundle))

    published = [(campaign, assessment, pack)]
    write_misp_feed(out_dir / "misp", published, tlp="TLP:CLEAR")
    (out_dir / "misp-event.json").write_bytes(
        serialize_event(build_misp_event(campaign, assessment, pack, tlp="TLP:CLEAR"))
    )
    write_feed(out_dir / "ioc-feed", published, refanged=False)

    context, graph_png = build_report_context(
        campaign,
        assessment,
        pack,
        tlp="TLP:CLEAR",
        stix_bundle_filename="stix-bundle.json",
    )
    if graph_png is None:
        raise RuntimeError("Graphviz (dot) is required to render the example campaign graph")
    graph_name = str(context["graph_png_filename"])
    (out_dir / graph_name).write_bytes(graph_png)
    (out_dir / "campaign-graph.png").write_bytes(graph_png)

    markdown_text = render_markdown(context)
    (out_dir / "report.md").write_text(markdown_text, encoding="utf-8")
    pdf_bytes = render_pdf(markdown_text, base_url=str(out_dir))
    (out_dir / "report.pdf").write_bytes(pdf_bytes)
    (out_dir / "README.md").write_text(_FOLDER_README, encoding="utf-8")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return int(port)


def _ensure_frontend() -> None:
    if (REPO_ROOT / "web" / "dist" / "index.html").is_file():
        return
    subprocess.check_call(["npm", "ci"], cwd=REPO_ROOT / "web")
    subprocess.check_call(["npm", "run", "build"], cwd=REPO_ROOT / "web")


def _capture_dashboard(db_path: Path, out_png: Path) -> None:
    _ensure_frontend()
    port = _free_port()
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite+pysqlite:///{db_path}"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "ledgerhound.api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        overview = f"http://127.0.0.1:{port}/api/overview"
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
                raise RuntimeError(f"dashboard process exited: {err}")
            try:
                with urllib.request.urlopen(overview, timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("dashboard did not answer /api/overview")

        from playwright.sync_api import sync_playwright

        url = f"http://127.0.0.1:{port}/campaigns/{CAMPAIGN_CODE}"
        with sync_playwright() as playwright:
            browser = None
            errors: list[str] = []
            launch_attempts: tuple[dict[str, Any], ...] = (
                {
                    "channel": "chrome",
                    "headless": True,
                    "args": ["--no-sandbox", "--disable-dev-shm-usage"],
                },
                {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]},
            )
            for kwargs in launch_attempts:
                try:
                    browser = playwright.chromium.launch(**kwargs)
                    break
                except Exception as exc:
                    errors.append(str(exc))
            if browser is None:
                raise RuntimeError("could not launch a browser: " + " | ".join(errors))
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.goto(url, wait_until="networkidle", timeout=30_000)
                page.get_by_text("Members (3)").wait_for(timeout=15_000)
                page.screenshot(path=str(out_png), full_page=True)
            finally:
                browser.close()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def build_example(out_dir: Path, *, screenshot: bool = True) -> None:
    """Write the LH-2026-001 example into `out_dir`. Replaces the directory."""
    out_dir = out_dir.resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    db_path = out_dir / "example.db"
    seq = _SeqUUID()
    saved = _swap_uuid_defaults(seq)
    try:
        with freeze_time(FROZEN_AT):
            session, engine = _open_session(db_path)
            try:
                fixture = _load_fixture()
                campaign = _populate(session, fixture)
                _write_artifacts(session, campaign, out_dir)
            finally:
                session.close()
                engine.dispose()
        if screenshot:
            _capture_dashboard(db_path, out_dir / "dashboard.png")
    finally:
        _restore_uuid_defaults(saved)
        if db_path.exists():
            db_path.unlink()


def main() -> None:
    destination = REPO_ROOT / "examples" / CAMPAIGN_CODE
    build_example(destination, screenshot=True)
    print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
