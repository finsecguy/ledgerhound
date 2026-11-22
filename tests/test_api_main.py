"""The FastAPI app factory: SPA static-file serving and its fallback
behavior. A client-side route (e.g. `/campaigns/LH-2026-001`, owned by
React Router, not a real file on disk) must still serve `index.html` so
a direct visit or page refresh doesn't 404, but an unmatched `/api/...`
path must remain a real 404, not silently turn into a 200 of the SPA
shell (a genuine bug found and fixed via live testing during
development, not caught by any earlier unit test).

The fallback also has to refuse paths that resolve outside the dist
directory. Encoded `..` segments and symlinks inside the tree can
otherwise read arbitrary files. Those requests fall back to
`index.html`, or 404 when the shell itself is not a file inside the root.
"""

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


def test_root_level_file_is_served_when_it_stays_inside_the_dist(
    dist_dir: Path,
) -> None:
    (dist_dir / "favicon.ico").write_text("ICON", encoding="utf-8")
    nested = dist_dir / "nested"
    nested.mkdir()
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert response.text == "ICON"

    # A `..` that normalizes back inside the dist is still that file.
    # `/assets/...` is served by the StaticFiles mount, so this uses a
    # directory the catch-all owns.
    response = client.get("/nested/%2e%2e/favicon.ico")
    assert response.status_code == 200
    assert response.text == "ICON"


def test_encoded_parent_segments_cannot_escape_the_static_root(
    dist_dir: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    for path in ("/%2e%2e/secret.txt", "/%2e%2e%2fsecret.txt", "/..%2fsecret.txt"):
        response = client.get(path)
        assert "TOP SECRET" not in response.text
        assert response.status_code == 200
        assert "app shell" in response.text


def test_symlink_outside_the_static_root_is_not_served(
    dist_dir: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    (dist_dir / "leak.txt").symlink_to(secret)
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/leak.txt")
    assert "TOP SECRET" not in response.text
    assert response.status_code == 200
    assert "app shell" in response.text


def test_symlink_inside_the_static_root_is_served(dist_dir: Path) -> None:
    target = dist_dir / "favicon.ico"
    target.write_text("ICON", encoding="utf-8")
    (dist_dir / "alias.ico").symlink_to(target)
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/alias.ico")
    assert response.status_code == 200
    assert response.text == "ICON"


def test_index_symlink_outside_the_static_root_is_not_served(
    dist_dir: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    index = dist_dir / "index.html"
    index.unlink()
    index.symlink_to(secret)
    from ledgerhound.api.main import create_app

    client = TestClient(create_app())
    response = client.get("/")
    assert "TOP SECRET" not in response.text
    assert response.status_code == 404


def test_resolve_static_file_rejects_absolute_and_parent_paths(tmp_path: Path) -> None:
    from ledgerhound.api.main import _resolve_static_file

    root = tmp_path / "dist"
    root.mkdir()
    index = root / "index.html"
    index.write_text("shell", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("nope", encoding="utf-8")

    assert _resolve_static_file(root, "../secret.txt") is None
    assert _resolve_static_file(root, "..\\secret.txt") is None
    assert _resolve_static_file(root, "/etc/passwd") is None
    assert _resolve_static_file(root, "\\etc\\passwd") is None
    assert _resolve_static_file(root, "") is None
    assert _resolve_static_file(root, "index.html") == index.resolve()
