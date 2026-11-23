"""Enrichment provider abstraction: the contract every data source implements,
plus the shared normalized shape chain providers converge on, and the one
network call path every provider is required to go through.

The whole enrichment layer is async (`httpx.AsyncClient`, `async def
enrich`): enrichment fans out across many independent network calls per
indicator and across many indicators concurrently, which is exactly what
asyncio is for. Milestone 1's collectors stay synchronous. This is scoped
to the enrichment layer only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

import httpx
import structlog
from pydantic import BaseModel, Field
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential

from ledgerhound.db.models import IndicatorType

logger = structlog.get_logger(__name__)

LabelType = Literal["exchange", "mixer", "bridge", "sanctioned", "scam"]
Chain = Literal["btc", "eth", "tron", "sol"]


class ProviderError(Exception):
    """Raised by a Provider when it cannot produce any usable result.

    Registry fallback triggers on this (and on any exception propagating
    out of `enrich`). Never on a successful-but-`partial` ProviderResult,
    which is a legitimate answer, just an incomplete one.
    """


@dataclass(frozen=True, slots=True)
class EnrichmentTarget:
    """The minimal, session-independent view of an indicator a Provider needs.

    Providers never see the SQLAlchemy ORM `Indicator` directly: enrichment
    runs many concurrent asyncio tasks, and ORM instances are bound to the
    sync `Session` that loaded them, not something safe to hand across
    concurrently-running tasks. The scheduler snapshots this immutable
    triple up front and that's all a Provider ever gets.
    """

    indicator_id: UUID
    type: IndicatorType
    value: str


@dataclass(frozen=True, slots=True)
class RateLimit:
    """`max_requests` requests per `per_seconds` window, enforced by the
    scheduler's per-provider token bucket (see `enrich/scheduler.py`)."""

    max_requests: int
    per_seconds: float


@dataclass(slots=True)
class ProviderResult[NormalizedT: BaseModel]:
    provider: str
    raw: dict[str, Any]
    normalized: NormalizedT
    fetched_at: datetime
    #: True when this provider answered with less than a full picture
    #: (e.g. a JSON-RPC balance check with no transaction history) rather
    #: than failing outright. Still a success for fallback purposes.
    partial: bool = False


# --- Shared normalized shape for all four chain providers -------------------
#
# "Chain-specific quirks stay inside the provider module and must not leak
# into the normalized model". Every one of btc.py/eth.py/tron.py/sol.py
# produces exactly this shape. Monetary values are `Decimal` in the chain's
# smallest native unit (satoshi/wei/sun/lamport). Never float, so nothing
# downstream (tracing, reports, clustering) ever rounds a wallet balance.


class Counterparty(BaseModel):
    address: str
    direction: Literal["in", "out"]
    tx_count: int
    total_value: Decimal


class AddressLabelHit(BaseModel):
    label: str
    label_type: LabelType
    source: str
    confidence: float


class ChainAddressProfile(BaseModel):
    chain: Chain
    address: str
    #: Power-of-ten divisor to reach the chain's display unit (8 for BTC,
    #: 18 for ETH, 6 for TRON, 9 for SOL). Values themselves stay in
    #: minor units; this is metadata for whoever renders them.
    decimals: int
    first_seen_onchain: datetime | None = None
    last_seen_onchain: datetime | None = None
    tx_count: int = 0
    total_received: Decimal = Decimal(0)
    total_sent: Decimal = Decimal(0)
    current_balance: Decimal = Decimal(0)
    counterparties: list[Counterparty] = Field(default_factory=list)
    labels: list[AddressLabelHit] = Field(default_factory=list)


# --- The one path to the network -------------------------------------------


def _is_retryable_http_error(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500 or exc.response.status_code == 429
    return isinstance(exc, httpx.TransportError)


async def http_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_attempts: int = 3,
    backoff_seconds: float = 1.0,
    **kwargs: Any,
) -> httpx.Response:
    """Every provider's only path to the network.

    Retries transport errors, 5xx, and 429 with exponential backoff; any
    other 4xx fails immediately since retrying won't help. No provider
    module is allowed to call `httpx`/`requests` directly. Everything
    routes through here (or `Provider.request`, a thin wrapper of this).
    """
    async for attempt in AsyncRetrying(
        retry=retry_if_exception(_is_retryable_http_error),
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=backoff_seconds),
        reraise=True,
    ):
        with attempt:
            response = await client.request(method, url, **kwargs)
            response.raise_for_status()
            return response
    raise AssertionError("unreachable: AsyncRetrying always raises or returns")


class Provider(ABC):
    """Base class for every enrichment data source."""

    name: str
    supports: set[IndicatorType]
    rate_limit: RateLimit
    ttl: timedelta

    def __init__(self, *, client: httpx.AsyncClient) -> None:
        self.client = client
        self.log = logger.bind(provider=self.name)

    @abstractmethod
    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[Any]:
        """Fetch and normalize data for `target`.

        Raise `ProviderError`, or let an `httpx`/parse exception propagate,
        if this provider cannot answer at all, the registry will fall
        back to the next provider in the chain. Return a `ProviderResult`
        with `partial=True` for a real but incomplete answer instead.
        """
        raise NotImplementedError

    async def request(
        self,
        method: str,
        url: str,
        *,
        max_attempts: int = 3,
        backoff_seconds: float = 1.0,
        **kwargs: Any,
    ) -> httpx.Response:
        return await http_request(
            self.client,
            method,
            url,
            max_attempts=max_attempts,
            backoff_seconds=backoff_seconds,
            **kwargs,
        )

