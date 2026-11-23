"""Config store: file/env default until an override is written, override
wins the moment it exists, invalid writes persist nothing, and `reset`
reverts cleanly, the same contract `lh config` and the dashboard's
Settings page both depend on."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from ledgerhound import config_store
from ledgerhound.config_store import ConfigValidationError


def test_runtime_defaults_to_settings_when_no_override(db_session: Session) -> None:
    assert config_store.is_overridden(db_session, "runtime") is False
    runtime = config_store.get_runtime_config(db_session)
    assert runtime.tlp_default == "TLP:CLEAR"
    assert runtime.llm_model == "gpt-4o-mini"


def test_set_runtime_config_is_read_back_immediately(db_session: Session) -> None:
    config_store.set_config(
        db_session,
        "runtime",
        {
            "llm_api_key": "sk-test",
            "llm_base_url": "https://example.test/v1",
            "llm_model": "custom-model",
            "tlp_default": "TLP:AMBER",
            "enrich_concurrency": 10,
            "enrich_default_ttl_hours": 12.0,
        },
    )

    assert config_store.is_overridden(db_session, "runtime") is True
    runtime = config_store.get_runtime_config(db_session)
    assert runtime.tlp_default == "TLP:AMBER"
    assert runtime.llm_model == "custom-model"
    assert runtime.enrich_concurrency == 10


def test_set_config_rejects_invalid_value_and_persists_nothing(db_session: Session) -> None:
    with pytest.raises(ConfigValidationError):
        config_store.set_config(db_session, "runtime", {"enrich_concurrency": "not-a-number"})

    assert config_store.is_overridden(db_session, "runtime") is False


def test_reset_reverts_to_file_env_default(db_session: Session) -> None:
    config_store.set_config(db_session, "runtime", {"tlp_default": "TLP:RED"})
    assert config_store.get_runtime_config(db_session).tlp_default == "TLP:RED"

    config_store.reset_config(db_session, "runtime")

    assert config_store.is_overridden(db_session, "runtime") is False
    assert config_store.get_runtime_config(db_session).tlp_default == "TLP:CLEAR"


def test_reset_on_a_domain_with_no_override_is_a_no_op(db_session: Session) -> None:
    config_store.reset_config(db_session, "clustering")  # must not raise
    assert config_store.is_overridden(db_session, "clustering") is False


def test_clustering_override_reflected_in_get_config(db_session: Session) -> None:
    raw = config_store.get_clustering_config(db_session).model_dump(mode="json")
    raw["campaign"]["score_threshold"] = 0.9
    config_store.set_config(db_session, "clustering", raw)

    updated = config_store.get_clustering_config(db_session)
    assert updated.campaign.score_threshold == 0.9


def test_sources_override_replaces_the_whole_list(db_session: Session) -> None:
    config_store.set_config(
        db_session,
        "sources",
        {
            "sources": [
                {
                    "name": "scamsniffer",
                    "type": "phishing_feed",
                    "url": "https://example.test/feed",
                    "cadence_minutes": 30,
                    "reliability_grade": "B",
                    "enabled": False,
                }
            ]
        },
    )

    sources = config_store.get_sources_config(db_session)
    assert len(sources) == 1
    assert sources[0].enabled is False
    assert sources[0].cadence_minutes == 30


def test_providers_override_is_read_back_by_name(db_session: Session) -> None:
    config_store.set_config(
        db_session,
        "providers",
        {"providers": {"mempool_space": {"max_requests": 99, "per_seconds": 10, "ttl_hours": 6}}},
    )

    providers = config_store.get_providers_config(db_session)
    assert providers["mempool_space"].max_requests == 99


def test_list_config_reports_override_status_per_domain(db_session: Session) -> None:
    config_store.set_config(db_session, "runtime", {"tlp_default": "TLP:AMBER"})

    listing = config_store.list_config(db_session)

    assert set(listing) == set(config_store.DOMAINS)
    _, runtime_overridden = listing["runtime"]
    assert runtime_overridden is True
    _, clustering_overridden = listing["clustering"]
    assert clustering_overridden is False

