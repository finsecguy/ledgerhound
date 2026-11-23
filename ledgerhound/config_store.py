"""GUI/CLI-editable config, layered over the file/env defaults.

Four domains: `sources`, `providers`, and `clustering` each mirror one
of `config/*.yaml`, validated with that domain's existing pydantic
model; `runtime` covers the handful of `Settings` fields worth changing
without a redeploy (the assessment-drafting LLM backend, the default TLP
marking, enrichment concurrency/TTL). A domain's row in
`config_overrides` (see `db/models.py`) takes precedence the moment it
exists. `set_config` validates and writes it, taking effect on the very
next read, no restart; `reset_config` deletes the row, reverting to that
domain's file/env default.

`DATABASE_URL` and logging are deliberately never part of this store:
both are needed before this table can be reached (or before there's
anywhere to log to), so they stay `.env`-only. Filesystem paths
(`*_config_path`, `*_cache_path`, `export_output_path`, `reports_path`)
and HTTP retry tuning stay `.env`-only too. Server-local paths and
low-level retry knobs aren't what a GUI settings page is for.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from ledgerhound.cluster.config import ClusteringConfig, load_clustering_config
from ledgerhound.collect import SourceConfig, SourcesConfig, load_sources_config
from ledgerhound.db.models import ConfigOverride
from ledgerhound.enrich.registry import ProviderConfigEntry, ProvidersConfig, load_providers_config
from ledgerhound.settings import Settings, get_settings

Domain = Literal["sources", "providers", "clustering", "runtime"]
DOMAINS: tuple[Domain, ...] = ("sources", "providers", "clustering", "runtime")


class RuntimeConfig(BaseModel):
    """The `Settings` fields exposed for live editing. See the module
    docstring for what's deliberately excluded and why."""

    llm_api_key: str | None = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    tlp_default: str = "TLP:CLEAR"
    enrich_concurrency: int = 5
    enrich_default_ttl_hours: float = 6.0

    @classmethod
    def from_settings(cls, settings: Settings) -> RuntimeConfig:
        return cls(
            llm_api_key=settings.llm_api_key,
            llm_base_url=settings.llm_base_url,
            llm_model=settings.llm_model,
            tlp_default=settings.tlp_default,
            enrich_concurrency=settings.enrich_concurrency,
            enrich_default_ttl_hours=settings.enrich_default_ttl_hours,
        )


class ConfigValidationError(Exception):
    """Raised when `set_config` is given a value that fails its domain's
    schema. Nothing is persisted when this is raised."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


_MODEL_BY_DOMAIN: dict[Domain, type[BaseModel]] = {
    "sources": SourcesConfig,
    "providers": ProvidersConfig,
    "clustering": ClusteringConfig,
    "runtime": RuntimeConfig,
}


def _model_for(domain: Domain) -> type[BaseModel]:
    return _MODEL_BY_DOMAIN[domain]


def _row(session: Session, domain: Domain) -> ConfigOverride | None:
    return session.get(ConfigOverride, domain)


def is_overridden(session: Session, domain: Domain) -> bool:
    return _row(session, domain) is not None


def get_sources_config(session: Session) -> list[SourceConfig]:
    row = _row(session, "sources")
    if row is not None:
        return SourcesConfig.model_validate(row.value).sources
    return load_sources_config(get_settings().sources_config_path)


def get_providers_config(session: Session) -> dict[str, ProviderConfigEntry]:
    row = _row(session, "providers")
    if row is not None:
        return ProvidersConfig.model_validate(row.value).providers
    return load_providers_config(get_settings().providers_config_path)


def get_clustering_config(session: Session) -> ClusteringConfig:
    row = _row(session, "clustering")
    if row is not None:
        return ClusteringConfig.model_validate(row.value)
    return load_clustering_config(get_settings().clustering_config_path)


def get_runtime_config(session: Session) -> RuntimeConfig:
    row = _row(session, "runtime")
    if row is not None:
        return RuntimeConfig.model_validate(row.value)
    return RuntimeConfig.from_settings(get_settings())


def get_config(session: Session, domain: Domain) -> BaseModel:
    """The effective value for `domain`, its override if one exists,
    otherwise its file/env default, as that domain's whole pydantic
    model (matching the shape `set_config` expects back)."""
    if domain == "sources":
        return SourcesConfig(sources=get_sources_config(session))
    if domain == "providers":
        return ProvidersConfig(providers=get_providers_config(session))
    if domain == "clustering":
        return get_clustering_config(session)
    return get_runtime_config(session)


def list_config(session: Session) -> dict[Domain, tuple[BaseModel, bool]]:
    """Every domain's (effective value, is_overridden) pair. What a
    `lh config show` or the dashboard Settings page renders."""
    return {
        domain: (get_config(session, domain), is_overridden(session, domain)) for domain in DOMAINS
    }


def set_config(
    session: Session, domain: Domain, raw: dict[str, Any], *, updated_by: str | None = None
) -> BaseModel:
    """Validate `raw` against `domain`'s schema and persist it as that
    domain's override, taking effect on the very next read, no restart,
    no file write. Nothing is written if validation fails."""
    model = _model_for(domain)
    try:
        validated = model.model_validate(raw)
    except ValidationError as exc:
        raise ConfigValidationError([str(exc)]) from exc

    value = validated.model_dump(mode="json")
    row = _row(session, domain)
    if row is None:
        session.add(ConfigOverride(key=domain, value=value, updated_by=updated_by))
    else:
        row.value = value
        row.updated_by = updated_by
    session.flush()
    return validated


def reset_config(session: Session, domain: Domain) -> None:
    """Delete `domain`'s override, reverting to its file/env default."""
    row = _row(session, domain)
    if row is not None:
        session.delete(row)
        session.flush()

