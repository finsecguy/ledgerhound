"""The FastAPI app factory: SPA static-file serving and its fallback
behavior. A client-side route (e.g. `/campaigns/LH-2026-001`, owned by
React Router, not a real file on disk) must still serve `index.html` so
a direct visit or page refresh doesn't 404 — but an unmatched `/api/...`
path must remain a real 404, not silently turn into a 200 of the SPA
shell (a genuine bug found and fixed via live testing during
development, not caught by any earlier unit test)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def dist_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html><body>app shell</body></html>", encoding="utf-8")
    assets = dist / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("console.log('hi');", encoding="utf-8")

    import ledgerhound.api.main as main_module

    monkeypatch.setattr(main_module, "WEB_DIST_DIR", dist)
    return dist


def test_root_serves_index_html(dist_dir: Path) -> None:
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/")
    assert response.status_code == 200
    assert "app shell" in response.text


def test_client_side_route_falls_back_to_index_html(dist_dir: Path) -> None:
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/campaigns/LH-2026-001")
    assert response.status_code == 200
    assert "app shell" in response.text


def test_real_asset_file_is_served_as_itself(dist_dir: Path) -> None:
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/assets/app.js")
    assert response.status_code == 200
    assert "console.log" in response.text


def test_unmatched_api_path_is_a_real_404_not_the_spa_shell(dist_dir: Path) -> None:
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert "app shell" not in response.text


def test_no_dist_dir_means_no_frontend_serving_at_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ledgerhound.api.main as main_module

    monkeypatch.setattr(main_module, "WEB_DIST_DIR", tmp_path / "does-not-exist")
    client = TestClient(main_module.create_app())
    response = client.get("/")
    assert response.status_code == 404
