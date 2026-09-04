"""ETH provider tests (Blockscout + public-RPC fallback), plus the
registry-level fallback behavior test: primary fails, secondary serves,
and the result is marked with the correct serving provider."""

from __future__ import annotations

import json
from decimal import Decimal
from uuid import uuid4

import httpx

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget
from ledgerhound.enrich.chain.eth import BlockscoutEthProvider, PublicRpcEthProvider
from ledgerhound.enrich.registry import ProviderRegistry

ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
COUNTERPARTY = "0x6181a4c5566051081b70d9348db673ee83ca0313"

BLOCKSCOUT_ADDRESS = {"coin_balance": "6712150161831460931"}
BLOCKSCOUT_COUNTERS = {"transactions_count": "2"}
BLOCKSCOUT_TXS = {
    "items": [
        {
            "timestamp": "2026-07-19T13:22:08.000000Z",
            "from": {"hash": ADDRESS},
            "to": {"hash": COUNTERPARTY},
            "value": "30000000000000000",
        },
        {
            "timestamp": "2026-07-14T07:04:22.000000Z",
            "from": {"hash": COUNTERPARTY},
            "to": {"hash": ADDRESS},
            "value": "10000000000000000",
        },
    ],
    "next_page_params": None,
}


def _blockscout_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/counters"):
        return httpx.Response(200, json=BLOCKSCOUT_COUNTERS)
    if path.endswith("/transactions"):
        return httpx.Response(200, json=BLOCKSCOUT_TXS)
    if path.endswith(f"/addresses/{ADDRESS}"):
        return httpx.Response(200, json=BLOCKSCOUT_ADDRESS)
    return httpx.Response(404)


async def test_blockscout_parses_full_history_and_counterparties() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_blockscout_handler))
    provider = BlockscoutEthProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.ETH_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)
    profile = result.normalized

    assert result.provider == "blockscout_eth"
    assert not result.partial
    assert profile.current_balance == Decimal("6712150161831460931")
    assert profile.tx_count == 2
    by_direction = {c.direction: c for c in profile.counterparties}
    assert by_direction["out"].address == COUNTERPARTY.lower()
    assert by_direction["out"].total_value == Decimal("30000000000000000")
    assert by_direction["in"].total_value == Decimal("10000000000000000")


async def test_public_rpc_gives_partial_balance_only_result() -> None:
    def rpc_handler(request: httpx.Request) -> httpx.Response:
        method = json.loads(request.read())["method"]
        if method == "eth_getBalance":
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": "0x1000", "id": 1})
        if method == "eth_getTransactionCount":
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": "0x5", "id": 1})
        return httpx.Response(400)

    client = httpx.AsyncClient(transport=httpx.MockTransport(rpc_handler))
    provider = PublicRpcEthProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.ETH_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)

    assert result.provider == "publicnode_eth"
    assert result.partial is True
    assert result.normalized.current_balance == Decimal(0x1000)
    assert result.normalized.tx_count == 5
    assert result.normalized.counterparties == []


async def test_registry_falls_back_to_secondary_when_primary_fails() -> None:
    def failing_blockscout(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    def working_rpc(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": "0x2a", "id": 1})

    blockscout_client = httpx.AsyncClient(
        transport=httpx.MockTransport(failing_blockscout), timeout=1.0
    )
    rpc_client = httpx.AsyncClient(transport=httpx.MockTransport(working_rpc))

    # Give the failing provider a tiny retry backoff so this test doesn't
    # wait out the default exponential backoff.
    class FastFailBlockscout(BlockscoutEthProvider):
        async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:  # type: ignore[override]
            return await super().request(method, url, max_attempts=1, **kwargs)  # type: ignore[arg-type]

    registry = ProviderRegistry(
        {
            "eth_address": [
                FastFailBlockscout(client=blockscout_client),
                PublicRpcEthProvider(client=rpc_client),
            ]
        }
    )
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.ETH_ADDRESS, value=ADDRESS)

    result = await registry.enrich(target, "eth_address")

    assert result.provider == "publicnode_eth"
    assert result.partial is True

    snapshot = {row["provider"]: row for row in registry.health_snapshot()}
    assert snapshot["blockscout_eth"]["consecutive_failures"] == 1
    assert snapshot["blockscout_eth"]["healthy"] is False
    assert snapshot["publicnode_eth"]["healthy"] is True
    assert snapshot["publicnode_eth"]["consecutive_failures"] == 0
