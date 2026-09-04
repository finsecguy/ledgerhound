"""SOL provider tests: both providers are plain JSON-RPC (getBalance,
getSignaturesForAddress, getTransaction), schema verified live."""

from __future__ import annotations

import json
from decimal import Decimal
from uuid import uuid4

import httpx

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget
from ledgerhound.enrich.chain.sol import PublicNodeSolProvider, SolanaRpcProvider

ADDRESS = "11111111111111111111111111111111"
COUNTERPARTY = "22222222222222222222222222222222"

SIGNATURES = [
    {"signature": "sig1", "err": None, "blockTime": 1_700_000_000},
    {"signature": "sig2", "err": {"InstructionError": [0, "Custom"]}, "blockTime": 1_700_000_100},
]

# A simple two-account transfer: target receives 1000 lamports from
# COUNTERPARTY, minus no fee complications for a clean assertion.
TRANSACTION = {
    "blockTime": 1_700_000_000,
    "transaction": {"message": {"accountKeys": [ADDRESS, COUNTERPARTY]}},
    "meta": {"preBalances": [500, 2000], "postBalances": [1500, 1000]},
}


def _rpc_handler(request: httpx.Request) -> httpx.Response:
    method = json.loads(request.read())["method"]
    if method == "getBalance":
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": {"value": 1500}, "id": 1})
    if method == "getSignaturesForAddress":
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": SIGNATURES, "id": 1})
    if method == "getTransaction":
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": TRANSACTION, "id": 1})
    return httpx.Response(400)


async def test_solana_rpc_parses_balance_and_counterparty_from_delta() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_rpc_handler))
    provider = SolanaRpcProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.SOL_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)
    profile = result.normalized

    assert result.provider == "solana_rpc"
    assert result.partial is True  # always partial: heuristic counterparty attribution
    assert profile.current_balance == Decimal(1500)
    # Only sig1 is inspected (sig2 errored and is skipped); target gained
    # 1000 lamports, COUNTERPARTY lost 1000 -> attributed as the sender.
    assert len(profile.counterparties) == 1
    cp = profile.counterparties[0]
    assert cp.address == COUNTERPARTY
    assert cp.direction == "in"
    assert cp.total_value == Decimal(1000)


async def test_publicnode_sol_produces_same_shape() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_rpc_handler))
    provider = PublicNodeSolProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.SOL_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)

    assert result.provider == "publicnode_sol"
    assert result.normalized.current_balance == Decimal(1500)
