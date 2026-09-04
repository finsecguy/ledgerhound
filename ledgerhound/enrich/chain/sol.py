"""Solana address enrichment: two independent public JSON-RPC endpoints.

Unlike Ethereum, Solana's own RPC exposes `getSignaturesForAddress` — a
real address-history method, no separate indexer needed — so both
providers here are plain JSON-RPC and both give the full picture. That
makes this the one chain where two *actually equivalent* keyless
providers were available, rather than a rich-primary/thin-fallback pair.

Counterparty attribution is a heuristic: a modern Solana transaction can
touch dozens of accounts (compute budget, token programs, swap routers),
and there's no single correct answer for "who is the counterparty" the
way there is for a simple two-party BTC/ETH transfer. For each inspected
transaction we take the target address's own balance delta (exact, from
`preBalances`/`postBalances`) and attribute it to whichever other
non-program account moved the largest opposite-signed amount — a
reasonable guess for simple transfers, a rough one for complex DeFi
transactions. Always marked `partial=True` for this reason.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import (
    ChainAddressProfile,
    Counterparty,
    EnrichmentTarget,
    Provider,
    ProviderResult,
    RateLimit,
)

SOL_DECIMALS = 9
_MAX_TX_INSPECTED = 15
_SIGNATURES_PAGE_LIMIT = 1000

#: Well-known program/system accounts excluded from counterparty
#: attribution — a balance delta on one of these is a fee/rent artifact,
#: not a meaningful counterparty.
_PROGRAM_IDS = {
    "11111111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
}


class _SolanaRpcProvider(Provider):
    supports = {IndicatorType.SOL_ADDRESS}
    ttl = timedelta(hours=6)

    def __init__(self, *, rpc_url: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.rpc_url = rpc_url

    async def _rpc(self, method: str, params: list[Any]) -> Any:
        response = await self.request(
            "POST",
            self.rpc_url,
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        )
        payload = response.json()
        if "error" in payload:
            raise RuntimeError(f"RPC error calling {method}: {payload['error']}")
        return payload["result"]

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
        address = target.value
        balance_result = await self._rpc("getBalance", [address])
        balance = int(balance_result["value"])

        signatures = await self._rpc(
            "getSignaturesForAddress", [address, {"limit": _SIGNATURES_PAGE_LIMIT}]
        )
        successful = [sig for sig in signatures if sig.get("err") is None]
        block_times = [sig["blockTime"] for sig in signatures if sig.get("blockTime")]
        first_seen = datetime.fromtimestamp(min(block_times), tz=UTC) if block_times else None
        last_seen = datetime.fromtimestamp(max(block_times), tz=UTC) if block_times else None

        agg: dict[tuple[str, str], list[int]] = {}
        raw_txs: list[dict[str, Any]] = []
        for sig_info in successful[:_MAX_TX_INSPECTED]:
            tx = await self._rpc(
                "getTransaction",
                [
                    sig_info["signature"],
                    {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
                ],
            )
            if tx is None:
                continue
            raw_txs.append(tx)
            meta = tx.get("meta") or {}
            pre = meta.get("preBalances") or []
            post = meta.get("postBalances") or []
            account_keys = [
                key["pubkey"] if isinstance(key, dict) else key
                for key in tx["transaction"]["message"]["accountKeys"]
            ]
            if address not in account_keys or len(pre) != len(post):
                continue
            target_index = account_keys.index(address)
            target_delta = post[target_index] - pre[target_index]
            if target_delta == 0:
                continue
            direction = "in" if target_delta > 0 else "out"

            best_counterparty: str | None = None
            best_opposite_delta = 0
            for i, key in enumerate(account_keys):
                if i == target_index or key in _PROGRAM_IDS:
                    continue
                delta = post[i] - pre[i]
                if target_delta > 0 and delta < best_opposite_delta:
                    best_opposite_delta = delta
                    best_counterparty = key
                elif target_delta < 0 and delta > best_opposite_delta:
                    best_opposite_delta = delta
                    best_counterparty = key

            if best_counterparty is None:
                continue
            key = (best_counterparty, direction)
            agg.setdefault(key, [0, 0])
            agg[key][0] += 1
            agg[key][1] += abs(target_delta)

        counterparties = [
            Counterparty(
                address=addr, direction=direction, tx_count=count, total_value=Decimal(value)
            )
            for (addr, direction), (count, value) in sorted(
                agg.items(), key=lambda kv: kv[1][1], reverse=True
            )
        ]
        total_in = sum((c.total_value for c in counterparties if c.direction == "in"), Decimal(0))
        total_out = sum(
            (c.total_value for c in counterparties if c.direction == "out"), Decimal(0)
        )

        profile = ChainAddressProfile(
            chain="sol",
            address=address,
            decimals=SOL_DECIMALS,
            first_seen_onchain=first_seen,
            last_seen_onchain=last_seen,
            tx_count=len(signatures),
            total_received=total_in,
            total_sent=total_out,
            current_balance=Decimal(balance),
            counterparties=counterparties,
        )
        return ProviderResult(
            provider=self.name,
            raw={"balance": balance_result, "signatures": signatures, "transactions": raw_txs},
            normalized=profile,
            fetched_at=datetime.now(UTC),
            partial=True,
        )


class SolanaRpcProvider(_SolanaRpcProvider):
    name = "solana_rpc"
    rate_limit = RateLimit(max_requests=10, per_seconds=10)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(rpc_url="https://api.mainnet-beta.solana.com", **kwargs)


class PublicNodeSolProvider(_SolanaRpcProvider):
    name = "publicnode_sol"
    rate_limit = RateLimit(max_requests=10, per_seconds=10)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(rpc_url="https://solana-rpc.publicnode.com", **kwargs)
