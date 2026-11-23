"""Engine and session factory management.

A single process-wide `Engine` is created lazily from `Settings.database_url`
and cached. Tests construct their own engine/sessionmaker pointed at a
throwaway SQLite database rather than using this module, so nothing here
is SQLite-specific.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from ledgerhound.settings import get_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    settings = get_settings()
    url = settings.database_url
    # The dashboard can serve a local SQLite file (the sanitised example
    # does). Sync FastAPI handlers run in a worker thread, so the default
    # SQLite check_same_thread guard would reject those requests.
    if url.startswith("sqlite"):
        return create_engine(
            url,
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(url, pool_pre_ping=True, future=True)


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Yield a Session; commit on clean exit, roll back and re-raise on error."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
