"""Dialect-portable column types.

Production Ledgerhound runs on Postgres 16 and the schema is designed
around Postgres-native `UUID` and `JSONB` columns. The test suite runs
against SQLite (no network/Docker dependency), which has neither type
natively. These `TypeDecorator`s pick the native Postgres type when
available and fall back to an equivalent portable representation
otherwise, so the exact same model definitions work correctly against
both engines.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import CHAR, JSON, DateTime, Numeric, String, types
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Dialect


class GUID(types.TypeDecorator[uuid.UUID]):
    """Platform-independent UUID column.

    Uses Postgres's native `UUID` type when talking to Postgres, and a
    `CHAR(36)` (stringified UUID) everywhere else.
    """

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> types.TypeEngine[Any]:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql.UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value: Any, dialect: Dialect) -> Any:
        if value is None:
            return None
        if dialect.name == "postgresql":
            return str(value)
        if not isinstance(value, uuid.UUID):
            value = uuid.UUID(str(value))
        return str(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> uuid.UUID | None:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class JSONB(types.TypeDecorator[dict[str, Any]]):
    """Platform-independent JSON column.

    Uses Postgres's native `JSONB` type when talking to Postgres, and
    SQLAlchemy's generic `JSON` (stored as TEXT) everywhere else.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> types.TypeEngine[Any]:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql.JSONB())
        return dialect.type_descriptor(JSON())


class UTCDateTime(types.TypeDecorator[datetime]):
    """Timezone-aware UTC datetime column.

    Postgres's `TIMESTAMPTZ` round-trips aware datetimes natively via
    psycopg. SQLite has no timezone-aware datetime type at all — values
    would silently come back naive on read, which is exactly the kind of
    bug that only shows up once something compares an old row's timestamp
    against a freshly-constructed `datetime.now(UTC)`. To keep behavior
    identical across dialects, non-Postgres backends store naive UTC and
    this type re-attaches `tzinfo=UTC` on the way back out.
    """

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> types.TypeEngine[Any]:
        return dialect.type_descriptor(DateTime(timezone=(dialect.name == "postgresql")))

    def process_bind_param(self, value: Any, dialect: Dialect) -> Any:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError(f"UTCDateTime requires a timezone-aware value, got {value!r}")
        if dialect.name == "postgresql":
            return value
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class PreciseNumeric(types.TypeDecorator[Decimal]):
    """Arbitrary-precision decimal column, exact on every dialect.

    Postgres's native `NUMERIC` is already exact and arbitrary-precision,
    so it's used directly there. SQLite has no fixed-point decimal type —
    plain `sqlalchemy.Numeric` silently stores SQLite values as a
    floating-point `REAL` column, which rounds (confirmed empirically:
    an 18-decimal-place wei amount comes back changed in the last several
    digits). Since on-chain values routinely need exact arbitrary
    precision (wei, satoshi totals, cumulative fund-flow sums), non-
    Postgres backends store the Decimal's exact string form as `TEXT`
    instead and parse it back on read — the same trick as `JSONB` and
    `GUID` above, applied to the one place a silent float conversion
    would actually corrupt data.
    """

    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> types.TypeEngine[Any]:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(Numeric())
        return dialect.type_descriptor(String())

    def process_bind_param(self, value: Any, dialect: Dialect) -> Any:
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return str(Decimal(value))

    def process_result_value(self, value: Any, dialect: Dialect) -> Decimal | None:
        if value is None:
            return None
        if isinstance(value, Decimal):
            return value
        return Decimal(str(value))
