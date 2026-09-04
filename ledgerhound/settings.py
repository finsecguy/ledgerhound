"""Application configuration.

All configuration is sourced from environment variables (optionally via a
`.env` file for local development) through pydantic-settings. Nothing
secret is ever hard-coded; see `.env.example` for the full set of knobs.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-wide settings, loaded once and cached.

    Values fall back to sane local-development defaults so the tool is
    usable out of the box against the bundled docker-compose Postgres, but
    every value is expected to be overridden via the environment in any
    real deployment.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql+psycopg://ledgerhound:ledgerhound@localhost:5432/ledgerhound",
        description="SQLAlchemy connection URL for the primary Postgres database.",
    )

    http_timeout_seconds: float = Field(
        default=15.0,
        gt=0,
        description="Per-request timeout used by all collectors.",
    )
    http_user_agent: str = Field(
        default=(
            "Ledgerhound/0.1 (+https://github.com/ledgerhound/ledgerhound; "
            "threat-intel collection bot)"
        ),
        description="User-Agent header sent with every collector HTTP request.",
    )
    http_max_attempts: int = Field(
        default=3,
        ge=1,
        description="Number of attempts (including the first) before a fetch gives up.",
    )
    http_backoff_seconds: float = Field(
        default=1.0,
        gt=0,
        description="Base delay for exponential backoff between HTTP retry attempts.",
    )

    sources_config_path: Path = Field(
        default=Path("config/sources.yaml"),
        description="Path to the YAML file describing configured sources.",
    )
    providers_config_path: Path = Field(
        default=Path("config/providers.yaml"),
        description="Path to the YAML file tuning per-provider rate limits/TTLs.",
    )
    clustering_config_path: Path = Field(
        default=Path("config/clustering.yaml"),
        description="Path to the YAML file tuning relation weights and campaign thresholds.",
    )

    enrich_concurrency: int = Field(
        default=5,
        gt=0,
        description="Max number of indicators being actively enriched (network calls) at once.",
    )
    enrich_default_ttl_hours: float = Field(
        default=6.0,
        gt=0,
        description=(
            "How long an indicator's enrichment stays fresh before `lh enrich` re-fetches it."
        ),
    )
    ofac_cache_path: Path = Field(
        default=Path(".cache/ofac_sdn.xml"),
        description="Local cache path for the OFAC SDN list download.",
    )
    rdap_bootstrap_cache_path: Path = Field(
        default=Path(".cache/rdap_bootstrap.json"),
        description="Local cache path for IANA's RDAP bootstrap registry (24h TTL).",
    )
    known_addresses_path: Path | None = Field(
        default=None,
        description=(
            "Override path for the known-address label dataset "
            "(mixers/bridges/exchanges); defaults to the bundled file."
        ),
    )

    llm_api_key: str | None = Field(
        default=None,
        description="API key for the assessment-drafting LLM. Required only for `lh assess draft`.",
    )
    llm_base_url: str = Field(
        default="https://api.openai.com/v1",
        description=(
            "Base URL of an OpenAI-compatible chat-completions API. Point this at "
            "Azure OpenAI, Ollama, LM Studio, Groq, Together, OpenRouter, vLLM, or "
            "any other provider speaking the same wire format to switch backends "
            "with no code change."
        ),
    )
    llm_model: str = Field(
        default="gpt-4o-mini",
        description="Model name passed to the assessment-drafting LLM's API.",
    )
    attack_stix_cache_path: Path = Field(
        default=Path(".cache/attack_enterprise.json"),
        description=(
            "Local cache for the distilled MITRE ATT&CK Enterprise technique dataset "
            "(technique id -> name), refreshed from MITRE's public STIX bundle."
        ),
    )

    export_output_path: Path = Field(
        default=Path("published"),
        description="Output root for `lh export stix/misp/feed` artifacts.",
    )
    reports_path: Path = Field(
        default=Path("reports"),
        description="Output root for `lh report render` / `lh publish` Markdown+PDF reports.",
    )
    tlp_default: str = Field(
        default="TLP:CLEAR",
        description="Default TLP marking applied to exported STIX/MISP/report artifacts.",
    )

    log_level: str = Field(default="INFO", description="Python logging level name.")
    log_json: bool = Field(
        default=False,
        description="Emit structlog output as JSON lines instead of console-friendly text.",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide Settings singleton."""
    return Settings()
