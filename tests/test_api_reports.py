"""Reports, IOC feed, and stats/overview endpoints: pure file reads and
`ledgerhound.stats.compute_stats` wrapping — nothing computed here that
isn't already computed by milestone 5's export layer or the shared
stats module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from ledgerhound.db.models import Campaign, Indicator, IndicatorType, RawReport, Source, SourceType

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _make_campaign(session: Session, code: str) -> Campaign:
    campaign = Campaign(
        code=code, status="active", score=1.0, relation_types=[], first_seen=NOW, last_seen=NOW
    )
    session.add(campaign)
    session.commit()
    return campaign


@pytest.fixture()
def reports_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from ledgerhound.settings import get_settings

    path = tmp_path / "reports"
    monkeypatch.setenv("REPORTS_PATH", str(path))
    get_settings.cache_clear()
    try:
        yield path
    finally:
        get_settings.cache_clear()


@pytest.fixture()
def export_output_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from ledgerhound.settings import get_settings

    path = tmp_path / "published"
    monkeypatch.setenv("EXPORT_OUTPUT_PATH", str(path))
    get_settings.cache_clear()
    try:
        yield path
    finally:
        get_settings.cache_clear()


def test_get_report_404_when_not_yet_published(
    db_session: Session, api_client: TestClient, reports_dir: Path
) -> None:
    _make_campaign(db_session, "LH-2026-001")
    response = api_client.get("/api/reports/LH-2026-001")
    assert response.status_code == 404


def test_get_report_returns_markdown_and_pdf_link(
    db_session: Session, api_client: TestClient, reports_dir: Path
) -> None:
    _make_campaign(db_session, "LH-2026-001")
    campaign_dir = reports_dir / "LH-2026-001"
    campaign_dir.mkdir(parents=True)
    (campaign_dir / "report.md").write_text("# 1. LH-2026-001\n\nSummary here.\n", encoding="utf-8")
    (campaign_dir / "report.pdf").write_bytes(b"%PDF-fake")

    response = api_client.get("/api/reports/LH-2026-001")
    assert response.status_code == 200
    body = response.json()
    assert body["has_markdown"] is True
    assert body["has_pdf"] is True
    assert "Summary here." in body["markdown"]
    assert body["pdf_url"] == "/api/reports/LH-2026-001/pdf"


def test_get_report_pdf_streams_the_file(
    db_session: Session, api_client: TestClient, reports_dir: Path
) -> None:
    _make_campaign(db_session, "LH-2026-001")
    campaign_dir = reports_dir / "LH-2026-001"
    campaign_dir.mkdir(parents=True)
    (campaign_dir / "report.md").write_text("# 1. LH-2026-001\n", encoding="utf-8")
    (campaign_dir / "report.pdf").write_bytes(b"%PDF-fake-bytes")

    response = api_client.get("/api/reports/LH-2026-001/pdf")
    assert response.status_code == 200
    assert response.content == b"%PDF-fake-bytes"
    assert response.headers["content-type"] == "application/pdf"


def test_get_report_pdf_404_without_a_pdf(
    db_session: Session, api_client: TestClient, reports_dir: Path
) -> None:
    _make_campaign(db_session, "LH-2026-001")
    campaign_dir = reports_dir / "LH-2026-001"
    campaign_dir.mkdir(parents=True)
    (campaign_dir / "report.md").write_text("# 1. LH-2026-001\n", encoding="utf-8")

    response = api_client.get("/api/reports/LH-2026-001/pdf")
    assert response.status_code == 404


def test_feed_index_404_when_never_exported(
    db_session: Session, api_client: TestClient, export_output_dir: Path
) -> None:
    response = api_client.get("/api/feed")
    assert response.status_code == 404


def test_feed_index_wraps_feed_json(
    db_session: Session, api_client: TestClient, export_output_dir: Path
) -> None:
    feed_dir = export_output_dir / "feed"
    feed_dir.mkdir(parents=True)
    (feed_dir / "feed.json").write_text(
        json.dumps(
            {
                "campaign_count": 1,
                "campaigns": [
                    {
                        "campaign": "LH-2026-001",
                        "status": "active",
                        "last_seen": "2026-01-01T00:00:00+00:00",
                        "indicator_count": 2,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    response = api_client.get("/api/feed")
    assert response.status_code == 200
    body = response.json()
    assert body["campaign_count"] == 1
    assert body["campaigns"][0]["campaign"] == "LH-2026-001"


def test_stats_wraps_compute_stats(db_session: Session, api_client: TestClient) -> None:
    source = Source(
        name="scamsniffer",
        type=SourceType.PHISHING_FEED,
        url="https://x",
        cadence_minutes=60,
        reliability_grade="B",
        enabled=True,
    )
    db_session.add(source)
    db_session.flush()
    db_session.add(RawReport(source_id=source.id, payload={}, content_hash="h1", fetched_at=NOW))
    db_session.add(
        Indicator(
            type=IndicatorType.ETH_ADDRESS,
            value="0xA",
            defanged_value="0xA",
            first_seen=NOW,
            last_seen=NOW,
        )
    )
    db_session.commit()

    response = api_client.get("/api/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["sources"][0]["name"] == "scamsniffer"
    assert body["sources"][0]["raw_report_count"] == 1
    assert body["total_indicators"] == 1


def test_overview_includes_stats_and_recent_campaigns(
    db_session: Session, api_client: TestClient
) -> None:
    _make_campaign(db_session, "LH-2026-001")
    response = api_client.get("/api/overview")
    assert response.status_code == 200
    body = response.json()
    assert "stats" in body
    assert body["recent_campaigns"][0]["code"] == "LH-2026-001"
