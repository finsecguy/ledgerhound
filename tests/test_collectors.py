"""Collector dedupe and resilience tests. No network access: httpx calls are
monkeypatched to return canned responses built from tests/fixtures/."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

import ledgerhound.collect.scamsniffer as scamsniffer_module
import ledgerhound.collect.urlhaus as urlhaus_module
from ledgerhound.collect.base import Collector, CollectorRunResult
from ledgerhound.collect.scamsniffer import ScamSnifferCollector
from ledgerhound.collect.urlhaus import URLhausCollector
from ledgerhound.db.models import RawReport, Source, SourceType
from ledgerhound.settings import Settings
from tests.conftest import load_fixture


@pytest.fixture()
def settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def _make_source(session: Session, name: str = "test-source") -> Source:
    source = Source(
        name=name,
        type=SourceType.PHISHING_FEED,
        url="https://example.invalid/feed",
        cadence_minutes=60,
        reliability_grade="B",
        enabled=True,
    )
    session.add(source)
    session.flush()
    return source


def _text_response(url: str, text: str) -> httpx.Response:
    return httpx.Response(200, text=text, request=httpx.Request("GET", url))


# --- ScamSniffer -------------------------------------------------------------


def test_scamsniffer_fetch_parses_domains_and_addresses(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    domains_json = load_fixture("scamsniffer_domains.json")
    address_json = load_fixture("scamsniffer_address.json")

    def fake_fetch_url(
        client: httpx.Client, url: str, *, settings: Settings | None = None, **kwargs: Any
    ) -> httpx.Response:
        if url == scamsniffer_module.DOMAINS_URL:
            return _text_response(url, domains_json)
        if url == scamsniffer_module.ADDRESS_URL:
            return _text_response(url, address_json)
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(scamsniffer_module, "fetch_url", fake_fetch_url)

    collector = ScamSnifferCollector(settings=settings)
    records = list(collector.fetch())

    # 4 valid domains ("" is malformed) + ... actually 3 valid non-empty domain
    # strings (blank, int, null skipped) + 3 valid addresses (blank skipped).
    domain_records = [r for r in records if r["list"] == "domains"]
    address_records = [r for r in records if r["list"] == "address"]
    assert {r["value"] for r in domain_records} == {
        "trust-wallet-bnb.vercel.app",
        "moonshot-voting-n7q.netlify.app",
        "manage-koinly.com",
    }
    assert {r["value"] for r in address_records} == {
        "0x101ce0cedd142f199c9ef61739ae59b6611a0fc0",
        "0x43412801d29861ecc4c4d86e5becfd16af86a67b",
        "0x51d07e2899c0ac6058b52c6f8f352f73d3f0e2e9",
    }


# --- URLhaus -------------------------------------------------------------


def test_urlhaus_fetch_parses_csv_skipping_malformed_row(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    csv_text = load_fixture("urlhaus_recent.csv")

    def fake_fetch_url(
        client: httpx.Client, url: str, *, settings: Settings | None = None, **kwargs: Any
    ) -> httpx.Response:
        return _text_response(url, csv_text)

    monkeypatch.setattr(urlhaus_module, "fetch_url", fake_fetch_url)

    collector = URLhausCollector(settings=settings)
    records = list(collector.fetch())

    # 4 well-formed data rows in the fixture; the malformed row is skipped.
    assert len(records) == 4
    ids = {r["id"] for r in records}
    assert ids == {"3911345", "3911344", "3911343", "3911342"}
    assert all(set(r.keys()) == {
        "id", "dateadded", "url", "url_status", "last_online", "threat", "tags",
        "urlhaus_link", "reporter",
    } for r in records)


# --- Base Collector: dedupe + resilience, chain-agnostic --------------------


class _FixedRecordsCollector(Collector):
    """Minimal Collector whose fetch() just replays a fixed record list,
    used to test base.run()'s dedupe/resilience/transaction behavior in
    isolation from any particular upstream feed format."""

    name = "fixed"

    def __init__(self, records: Iterable[dict[str, Any]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._records = list(records)

    def fetch(self) -> Iterable[dict[str, Any]]:
        return iter(self._records)

    def content_hash(self, record: dict[str, Any]) -> str:
        if record.get("_poison"):
            raise ValueError("simulated malformed record")
        return self.stable_hash(record)


def test_dedupe_same_record_fetched_twice_within_one_run_yields_one_row(
    db_session: Session, settings: Settings
) -> None:
    source = _make_source(db_session)
    record = {"value": "evil.example.com"}
    collector = _FixedRecordsCollector([record, dict(record)], settings=settings)

    result = collector.run(db_session, source)

    assert result.fetched == 2
    assert result.inserted == 1
    assert result.skipped_duplicate == 1
    stored = db_session.scalars(select(RawReport).where(RawReport.source_id == source.id)).all()
    assert len(stored) == 1


def test_dedupe_across_repeated_runs_yields_one_row(
    db_session: Session, settings: Settings
) -> None:
    source = _make_source(db_session)
    record = {"value": "evil.example.com"}

    first_result = _FixedRecordsCollector([record], settings=settings).run(db_session, source)
    second_result = _FixedRecordsCollector([record], settings=settings).run(db_session, source)

    assert first_result.inserted == 1
    assert second_result.inserted == 0
    assert second_result.skipped_duplicate == 1
    stored = db_session.scalars(select(RawReport).where(RawReport.source_id == source.id)).all()
    assert len(stored) == 1


def test_malformed_record_in_middle_of_batch_does_not_abort_run(
    db_session: Session, settings: Settings
) -> None:
    source = _make_source(db_session)
    records = [
        {"value": "good-one.example.com"},
        {"_poison": True},
        {"value": "good-two.example.com"},
    ]
    collector = _FixedRecordsCollector(records, settings=settings)

    result = collector.run(db_session, source)

    assert result.fetched == 3
    assert result.inserted == 2
    assert result.failed == 1
    stored = db_session.scalars(select(RawReport).where(RawReport.source_id == source.id)).all()
    assert len(stored) == 2


def test_run_returns_collector_run_result(db_session: Session, settings: Settings) -> None:
    source = _make_source(db_session)
    result = _FixedRecordsCollector([{"value": "x.example.com"}], settings=settings).run(
        db_session, source
    )
    assert isinstance(result, CollectorRunResult)
    assert result.source_name == "fixed"
