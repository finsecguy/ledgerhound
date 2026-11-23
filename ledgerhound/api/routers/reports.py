"""Report and IOC-feed endpoints: pure file reads against whatever `lh
report render` / `lh export feed` already wrote to disk. No rendering
happens here. This only surfaces artifacts milestone 5's export layer
already produced."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ledgerhound.api.deps import get_session
from ledgerhound.api.routers.campaigns import get_campaign_or_404
from ledgerhound.api.schemas.reports import FeedIndexOut, ReportMeta
from ledgerhound.settings import get_settings

router = APIRouter(prefix="/api/reports", tags=["reports"])
feed_router = APIRouter(prefix="/api/feed", tags=["feed"])


@router.get("/{code}", response_model=ReportMeta)
def get_report(code: str, session: Session = Depends(get_session)) -> ReportMeta:
    campaign = get_campaign_or_404(session, code)
    settings = get_settings()
    report_dir = settings.reports_path / campaign.code
    md_path = report_dir / "report.md"
    pdf_path = report_dir / "report.pdf"

    if not md_path.is_file():
        raise HTTPException(status_code=404, detail=f"{code} has no published report yet.")

    return ReportMeta(
        campaign_code=campaign.code,
        has_markdown=True,
        has_pdf=pdf_path.is_file(),
        markdown=md_path.read_text(encoding="utf-8"),
        pdf_url=f"/api/reports/{campaign.code}/pdf" if pdf_path.is_file() else None,
    )


@router.get("/{code}/pdf")
def get_report_pdf(code: str, session: Session = Depends(get_session)) -> FileResponse:
    campaign = get_campaign_or_404(session, code)
    settings = get_settings()
    pdf_path = settings.reports_path / campaign.code / "report.pdf"
    if not pdf_path.is_file():
        raise HTTPException(status_code=404, detail=f"{code} has no PDF report yet.")
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"{campaign.code}.pdf")


@feed_router.get("", response_model=FeedIndexOut)
def get_feed_index() -> FeedIndexOut:
    settings = get_settings()
    feed_json_path = settings.export_output_path / "feed" / "feed.json"
    if not feed_json_path.is_file():
        raise HTTPException(
            status_code=404, detail="No IOC feed has been exported yet (`lh export feed`)."
        )
    payload = json.loads(feed_json_path.read_text(encoding="utf-8"))
    return FeedIndexOut.model_validate(payload)


_FEED_MEDIA_TYPES = {".json": "application/json", ".csv": "text/csv", ".html": "text/html"}


@feed_router.get("/files/{filename}")
def get_feed_file(filename: str) -> FileResponse:
    """Serves one file from `<export_output_path>/feed/`, the per-
    campaign JSON, the combined `iocs.json`/`iocs.csv`, or `index.html`
    exactly as `lh export feed` wrote it. Resolved from settings fresh on
    every request (not baked in at app startup), same as the PDF
    endpoint above, since the export directory is written well after the
    API process starts."""
    if "/" in filename or "\\" in filename or filename in (".", ".."):
        raise HTTPException(status_code=400, detail="invalid filename")
    settings = get_settings()
    path = settings.export_output_path / "feed" / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"No such feed file: {filename!r}")
    media_type = _FEED_MEDIA_TYPES.get(path.suffix, "application/octet-stream")
    return FileResponse(path, media_type=media_type, filename=filename)

