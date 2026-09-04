"""FastAPI dependencies: a per-request DB session.

Reuses `db/session.py`'s process-wide engine/sessionmaker — the API
process and the CLI share the exact same database connection setup, no
separate config path.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy.orm import Session

from ledgerhound.db.session import get_sessionmaker


def get_session() -> Iterator[Session]:
    """Commit on a clean response, roll back on any exception — the same
    semantics as `db.session.session_scope`, adapted to FastAPI's
    generator-dependency lifecycle."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
