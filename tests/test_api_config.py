"""The config API: every route calls `ledgerhound.config_store` directly
(no re-expressed validation), so a bad write gets the same 422 the CLI's
`ConfigValidationError` produces, and a write via the API is immediately
visible to a direct `config_store` read, the API and `lh config` share
one store, not two copies of the truth."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from ledgerhound import config_store


def test_list_config_returns_all_four_domains(api_client: TestClient) -> None:
    response = api_client.get("/api/config")
    assert response.status_code == 200
    domains = {d["domain"] for d in response.json()["domains"]}
    assert domains == set(config_store.DOMAINS)


def test_get_one_domain_reports_not_overridden_by_default(api_client: TestClient) -> None:
    response = api_client.get("/api/config/runtime")
    assert response.status_code == 200
    body = response.json()
    assert body["overridden"] is False
    assert body["value"]["tlp_default"] == "TLP:CLEAR"


def test_put_valid_runtime_config_is_visible_to_a_direct_store_read(
    api_client: TestClient, db_session: Session
) -> None:
    current = api_client.get("/api/config/runtime").json()["value"]
    current["tlp_default"] = "TLP:AMBER"

    response = api_client.put("/api/config/runtime", json=current)

    assert response.status_code == 200
    assert response.json()["overridden"] is True
    assert config_store.get_runtime_config(db_session).tlp_default == "TLP:AMBER"


def test_put_invalid_runtime_config_returns_422_and_persists_nothing(
    api_client: TestClient, db_session: Session
) -> None:
    current = api_client.get("/api/config/runtime").json()["value"]
    current["enrich_concurrency"] = "not-a-number"

    response = api_client.put("/api/config/runtime", json=current)

    assert response.status_code == 422
    assert "errors" in response.json()["detail"]
    assert config_store.is_overridden(db_session, "runtime") is False


def test_reset_reverts_to_file_env_default(api_client: TestClient) -> None:
    current = api_client.get("/api/config/runtime").json()["value"]
    current["tlp_default"] = "TLP:RED"
    api_client.put("/api/config/runtime", json=current)

    response = api_client.post("/api/config/runtime/reset")

    assert response.status_code == 200
    assert response.json()["overridden"] is False
    assert response.json()["value"]["tlp_default"] == "TLP:CLEAR"


def test_unknown_domain_in_path_is_rejected(api_client: TestClient) -> None:
    response = api_client.get("/api/config/not-a-real-domain")
    assert response.status_code == 422


def test_sources_domain_round_trips_the_full_list(api_client: TestClient) -> None:
    payload = {
        "sources": [
            {
                "name": "scamsniffer",
                "type": "phishing_feed",
                "url": "https://example.test/feed",
                "cadence_minutes": 45,
                "reliability_grade": "B",
                "enabled": False,
            }
        ]
    }

    response = api_client.put("/api/config/sources", json=payload)

    assert response.status_code == 200
    sources = response.json()["value"]["sources"]
    assert len(sources) == 1
    assert sources[0]["enabled"] is False
    assert sources[0]["cadence_minutes"] == 45

