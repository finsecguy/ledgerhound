from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from ledgerhound.db.models import Base

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _ensure_stix2validator_schemas() -> None:
    """Work around a real packaging defect in `stix2-validator` on PyPI:
    the wheel (confirmed for 3.3.1) omits the `schemas-2.1/schemas/`
    directory it bundles upstream (a git submodule that isn't vendored
    into the sdist/wheel), so *every* validation call fails with
    "Cannot locate a schema for the object's type" regardless of the
    `-s`/`schema_dir` option — that option only adds extra schemas, it
    doesn't replace the missing built-in default lookup. Self-heals by
    copying our vendored copy (`tests/fixtures/stix2_schemas/`, pulled
    from `oasis-open/cti-stix2-json-schemas`) into the exact path the
    installed package expects, once per environment, idempotently.
    """
    try:
        import stix2validator.validator as v
    except ImportError:
        return
    target = Path(v.__file__).resolve().parent / "schemas-2.1" / "schemas"
    if target.is_dir():
        return
    source = FIXTURES_DIR / "stix2_schemas"
    if not source.is_dir():
        return
    shutil.copytree(source, target)


_ensure_stix2validator_schemas()


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture()
def db_session() -> Iterator[Session]:
    """A fresh in-memory SQLite database, schema created from the ORM models.

    `StaticPool` + `check_same_thread=False`: FastAPI's TestClient runs
    sync endpoint handlers in a worker thread, and plain sqlite3 refuses
    to touch a connection from any thread but the one that opened it —
    without this, an API test that seeds via this fixture and then calls
    the API in the same test fails with "SQLite objects created in a
    thread can only be used in that same thread." Safe here since
    access is always sequential (seed, then call), never concurrent.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def api_client(db_session: Session) -> Iterator[TestClient]:
    """A FastAPI TestClient wired to the same in-memory `db_session` a
    test seeds directly — the API's `get_session` dependency is
    overridden rather than pointed at a real file, so API tests share
    the exact seeding helpers/patterns the CLI-facing tests already use."""
    from ledgerhound.api.deps import get_session
    from ledgerhound.api.main import app

    def _override_get_session() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_session] = _override_get_session
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_session, None)


@pytest.fixture()
def attack_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A local ATT&CK cache file (T1566 -> Phishing) with `Settings`
    pointed at it, for any test exercising a code path that resolves
    `settings.attack_stix_cache_path` (the assessment-edit/draft API
    endpoints unconditionally load it, matching the CLI's own
    `lh assess edit`) — never a real network fetch. `get_settings` is
    `lru_cache`d process-wide, so it's explicitly cleared on both sides
    of the env var change or the new path would never actually be seen.
    """
    import json

    from ledgerhound.settings import get_settings

    cache_path = tmp_path / "attack_enterprise.json"
    cache_path.write_text(
        json.dumps(
            {
                "version": "19.2",
                "techniques": {"T1566": "Phishing"},
                "stix_ids": {"T1566": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ATTACK_STIX_CACHE_PATH", str(cache_path))
    get_settings.cache_clear()
    try:
        yield cache_path
    finally:
        get_settings.cache_clear()


def load_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")
