"""Collector base class: shared fetch/dedupe/persist machinery.

A concrete collector only has to know how to turn its upstream feed into
an iterable of JSON-ish dicts (`fetch`) and how to derive a stable hash
per record (`content_hash`). Everything else — retrying HTTP, deduping
against what's already stored, and committing the batch in one
transaction — lives here so every collector behaves identically.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from ledgerhound.db.models import RawReport, Source
from ledgerhound.settings import Settings, get_settings

logger = structlog.get_logger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    """Transient httpx errors worth retrying: connection issues, timeouts,
    and 5xx responses. 4xx responses are non-retryable client errors."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return isinstance(exc, httpx.TransportError)


@dataclass(frozen=True, slots=True)
class CollectorRunResult:
    """Summary of a single collector run, suitable for logging/reporting."""

    source_name: str
    fetched: int = 0
    inserted: int = 0
    skipped_duplicate: int = 0
    failed: int = 0


def fetch_url(
    client: httpx.Client,
    url: str,
    *,
    settings: Settings | None = None,
    **request_kwargs: Any,
) -> httpx.Response:
    """GET `url` with retry + exponential backoff, per Settings.

    Raises the last exception if every attempt is exhausted. 4xx responses
    raise immediately without retrying since retrying won't help.
    """
    settings = settings or get_settings()

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(settings.http_max_attempts),
        wait=wait_exponential(multiplier=settings.http_backoff_seconds, min=0),
        reraise=True,
    )
    def _do_fetch() -> httpx.Response:
        response = client.get(url, **request_kwargs)
        response.raise_for_status()
        return response

    return _do_fetch()


class Collector(ABC):
    """Base class for all feed collectors."""

    #: Must match a `name` entry in config/sources.yaml and the REGISTRY key.
    name: str

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.log = logger.bind(collector=self.name)

    def _build_client(self) -> httpx.Client:
        return httpx.Client(
            timeout=self.settings.http_timeout_seconds,
            headers={"User-Agent": self.settings.http_user_agent},
            follow_redirects=True,
        )

    @abstractmethod
    def fetch(self) -> Iterable[dict[str, Any]]:
        """Yield raw records from the upstream feed.

        Implementations MUST NOT let a single malformed upstream entry
        abort the whole feed: catch per-entry parse errors, log them, and
        continue yielding the rest.
        """
        raise NotImplementedError

    @abstractmethod
    def content_hash(self, record: dict[str, Any]) -> str:
        """Return a stable hex digest identifying this record's content."""
        raise NotImplementedError

    @staticmethod
    def stable_hash(record: dict[str, Any]) -> str:
        """Convenience: sha256 of a record's canonical JSON encoding."""
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def run(self, session: Session, source: Source) -> CollectorRunResult:
        """Fetch, dedupe, and persist new raw reports for `source`.

        All inserts happen in a single transaction: either every new
        record in this run lands, or (on an unexpected error) none does.
        Individual malformed records are skipped and counted, not fatal.
        """
        existing_hashes = set(
            session.scalars(
                select(RawReport.content_hash).where(RawReport.source_id == source.id)
            )
        )

        fetched = inserted = skipped_duplicate = failed = 0
        now = datetime.now(UTC)

        for record in self.fetch():
            fetched += 1
            try:
                content_hash = self.content_hash(record)
            except Exception:
                failed += 1
                self.log.warning("record_hash_failed", record=record)
                continue

            if content_hash in existing_hashes:
                skipped_duplicate += 1
                continue

            try:
                session.add(
                    RawReport(
                        source_id=source.id,
                        payload=record,
                        content_hash=content_hash,
                        fetched_at=now,
                    )
                )
            except Exception:
                failed += 1
                self.log.warning("record_persist_failed", record=record)
                continue

            existing_hashes.add(content_hash)
            inserted += 1

        session.commit()

        result = CollectorRunResult(
            source_name=self.name,
            fetched=fetched,
            inserted=inserted,
            skipped_duplicate=skipped_duplicate,
            failed=failed,
        )
        self.log.info(
            "collector_run_complete",
            fetched=fetched,
            inserted=inserted,
            skipped_duplicate=skipped_duplicate,
            failed=failed,
        )
        return result
