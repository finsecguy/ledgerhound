"""Collector registry and source-config loading.

`config/sources.yaml` is the single source of truth for which feeds
Ledgerhound knows about. It's loaded and validated through pydantic
(`SourceConfig`), then used to keep the `sources` table in sync
(`upsert_source`) and to pick which `Collector` implementation to run
(`REGISTRY`).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ledgerhound.collect.base import Collector
from ledgerhound.collect.scamsniffer import ScamSnifferCollector
from ledgerhound.collect.urlhaus import URLhausCollector
from ledgerhound.db.models import Source, SourceType

__all__ = [
    "REGISTRY",
    "SourceConfig",
    "SourcesConfig",
    "load_sources_config",
    "upsert_source",
]

REGISTRY: dict[str, type[Collector]] = {
    ScamSnifferCollector.name: ScamSnifferCollector,
    URLhausCollector.name: URLhausCollector,
}


class SourceConfig(BaseModel):
    """One entry from config/sources.yaml, validated."""

    name: str = Field(min_length=1)
    type: SourceType
    url: str = Field(min_length=1)
    cadence_minutes: int = Field(gt=0)
    reliability_grade: str = Field(pattern=r"^[A-F]$")
    enabled: bool = True


class SourcesConfig(BaseModel):
    """Top-level shape of config/sources.yaml."""

    sources: list[SourceConfig]


def load_sources_config(path: Path) -> list[SourceConfig]:
    """Load and validate the source registry YAML file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return SourcesConfig.model_validate(raw).sources


def upsert_source(session: Session, config: SourceConfig) -> Source:
    """Idempotently sync a `Source` row to match its YAML config."""
    source = session.scalar(select(Source).where(Source.name == config.name))
    if source is None:
        source = Source(
            name=config.name,
            type=config.type,
            url=config.url,
            cadence_minutes=config.cadence_minutes,
            reliability_grade=config.reliability_grade,
            enabled=config.enabled,
        )
        session.add(source)
    else:
        source.type = config.type
        source.url = config.url
        source.cadence_minutes = config.cadence_minutes
        source.reliability_grade = config.reliability_grade
        source.enabled = config.enabled
    session.flush()
    return source
