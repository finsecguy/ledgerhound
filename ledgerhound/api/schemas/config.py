"""Config domain response shapes. `value` is deliberately `dict[str,
Any]`, not a per-domain typed schema, the four domains have unrelated
shapes (a list for `sources`, nested weight groups for `clustering`,
etc.), and `ledgerhound.config_store` already validates every write
against that domain's real pydantic model before it's ever persisted, so
re-typing each shape again here would just be a second copy of the same
schema to keep in sync."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ledgerhound.config_store import Domain


class ConfigDomainOut(BaseModel):
    domain: Domain
    #: True once `lh config set` or this domain's PUT endpoint has ever
    #: been used. Otherwise `value` is that domain's file/env default.
    overridden: bool
    value: dict[str, Any]


class ConfigListOut(BaseModel):
    domains: list[ConfigDomainOut]

