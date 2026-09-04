"""BTC provider tests against recorded (hand-trimmed, schema-accurate)
Esplora API fixtures. No network: httpx.MockTransport intercepts every
request. Shapes verified against the real mempool.space/blockstream.info
APIs during development."""

from __future__ import annotations

from datetime import UTC
from decimal import Decimal
from uuid import uuid4

import httpx
import pytest

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget
from ledgerhound.enrich.chain.btc import BlockstreamProvider, MempoolSpaceProvider

ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

ADDRESS_STATS = {
    "address": ADDRESS,
    "chain_stats": {
        "funded_txo_count": 3,
        "funded_txo_sum": 300_000,
        "spent_txo_count": 1,
        "spent_txo_sum": 100_000,
        "tx_count": 2,
    },
    "mempool_stats": {
        "funded_txo_count": 0,
        "funded_txo_sum": 0,
        "spent_txo_count": 0,
        "spent_txo_sum": 0,
        "tx_count": 0,
    },
}

TXS_PAGE = [
    {
        "txid": "tx1",
        "vin": [
            {"prevout": {"scriptpubkey_address": "sender-addr-1", "value": 150_000}},
        ],
        "vout": [
            {"scriptpubkey_address": ADDRESS, "value": 150_000},
        ],
        "status": {"confirmed": True, "block_time": 1_700_000_000},
    },
    {
        "txid": "tx2",
        "vin": [
            {"prevout": {"scriptpubkey_address": ADDRESS, "value": 100_000}},
        ],
        "vout": [
            {"scriptpubkey_address": "receiver-addr-1", "value": 90_000},
            {"scriptpubkey_address": ADDRESS, "value": 9_000},  # change
        ],
        "status": {"confirmed": True, "block_time": 1_700_100_000},
    },
]


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith(f"/address/{ADDRESS}"):
        return httpx.Response(200, json=ADDRESS_STATS)
    if path.endswith(f"/address/{ADDRESS}/txs"):
        return httpx.Response(200, json=TXS_PAGE)
    if "/txs/chain/" in path:
        return httpx.Response(200, json=[])  # no further pages
    return httpx.Response(404)


@pytest.fixture()
def mock_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(_handler))


async def test_mempool_space_parses_balance_and_counterparties(
    mock_client: httpx.AsyncClient,
) -> None:
    provider = MempoolSpaceProvider(client=mock_client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.BTC_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)
    profile = result.normalized

    assert result.provider == "mempool_space"
    assert profile.chain == "btc"
    assert profile.tx_count == 2
    assert profile.total_received == Decimal(300_000)
    assert profile.total_sent == Decimal(100_000)
    assert profile.current_balance == Decimal(200_000)
    assert profile.first_seen_onchain is not None
    assert profile.first_seen_onchain.tzinfo is UTC
    assert not result.partial  # both txs fit in one page: full picture

    by_address = {c.address: c for c in profile.counterparties}
    assert by_address["sender-addr-1"].direction == "in"
    assert by_address["sender-addr-1"].total_value == Decimal(150_000)
    assert by_address["receiver-addr-1"].direction == "out"
    assert by_address["receiver-addr-1"].total_value == Decimal(90_000)


async def test_blockstream_produces_identical_shape(mock_client: httpx.AsyncClient) -> None:
    provider = BlockstreamProvider(client=mock_client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.BTC_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)

    assert result.provider == "blockstream"
    assert result.normalized.current_balance == Decimal(200_000)


async def test_partial_flag_set_when_more_txs_exist_than_fetched(
    mock_client: httpx.AsyncClient,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith(f"/address/{ADDRESS}"):
            stats = dict(ADDRESS_STATS)
            stats["chain_stats"] = dict(stats["chain_stats"], tx_count=999)
            return httpx.Response(200, json=stats)
        if path.endswith(f"/address/{ADDRESS}/txs") or "/txs/chain/" in path:
            return httpx.Response(200, json=TXS_PAGE)  # same page every time
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = MempoolSpaceProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.BTC_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)

    assert result.partial is True
