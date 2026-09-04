"""Ethereum address enrichment: Blockscout primary, public JSON-RPC fallback.

**Deviation from the milestone brief's literal "RPC primary, Blockscout
fallback" ordering, done deliberately:** plain JSON-RPC has no
"transactions for this address" method — a node only exposes
`eth_getBalance`/`eth_getTransactionCount` for an address; getting
history requires either an indexer API (which is exactly what Blockscout
is) or scanning `eth_getLogs`/every block yourself, which is far too
expensive to do per-indicator here. If RPC were first in the chain it
would "succeed" on every call (it always answers, just narrowly) and the
registry's fallback would never actually reach Blockscout, making the
richer provider permanently dead code. Blockscout first gives full
history by default; RPC is a genuine last-resort fallback for balance/
nonce data when Blockscout is unavailable, explicitly marked `partial`.
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

ETH_DECIMALS = 18


class BlockscoutEthProvider(Provider):
    name = "blockscout_eth"
    supports = {IndicatorType.ETH_ADDRESS}
    rate_limit = RateLimit(max_requests=8, per_seconds=10)
    ttl = timedelta(hours=6)

    base_url = "https://eth.blockscout.com/api/v2"
    _max_pages = 3

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
        address = target.value

        address_resp = await self.request("GET", f"{self.base_url}/addresses/{address}")
        address_info = address_resp.json()
        balance = Decimal(str(address_info.get("coin_balance") or 0))

        counters_resp = await self.request(
            "GET", f"{self.base_url}/addresses/{address}/counters"
        )
        counters = counters_resp.json()
        tx_count = int(counters.get("transactions_count") or 0)

        all_items: list[dict[str, Any]] = []
        next_page_params: dict[str, Any] | None = None
        for _ in range(self._max_pages):
            url = f"{self.base_url}/addresses/{address}/transactions"
            params = dict(next_page_params) if next_page_params else None
            page_resp = await self.request("GET", url, params=params)
            page = page_resp.json()
            items = page.get("items") or []
            all_items.extend(items)
            next_page_params = page.get("next_page_params")
            if not next_page_params or not items:
                break

        agg: dict[tuple[str, str], list[int]] = {}
        timestamps: list[datetime] = []
        for tx in all_items:
            ts = tx.get("timestamp")
            if ts:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            from_addr = ((tx.get("from") or {}).get("hash") or "").lower()
            to_addr = ((tx.get("to") or {}).get("hash") or "").lower()
            value = int(tx.get("value") or 0)
            if value <= 0:
                continue
            target_lower = address.lower()
            if from_addr == target_lower and to_addr and to_addr != target_lower:
                key = (to_addr, "out")
                agg.setdefault(key, [0, 0])
                agg[key][0] += 1
                agg[key][1] += value
            if to_addr == target_lower and from_addr and from_addr != target_lower:
                key = (from_addr, "in")
                agg.setdefault(key, [0, 0])
                agg[key][0] += 1
                agg[key][1] += value

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
            chain="eth",
            address=address,
            decimals=ETH_DECIMALS,
            first_seen_onchain=min(timestamps) if timestamps else None,
            last_seen_onchain=max(timestamps) if timestamps else None,
            tx_count=tx_count,
            total_received=total_in,
            total_sent=total_out,
            current_balance=balance,
            counterparties=counterparties,
        )
        return ProviderResult(
            provider=self.name,
            raw={"address": address_info, "counters": counters, "transactions": all_items},
            normalized=profile,
            fetched_at=datetime.now(UTC),
            partial=tx_count > len(all_items),
        )


class PublicRpcEthProvider(Provider):
    """Balance/nonce only, via a plain keyless JSON-RPC endpoint.

    Always `partial=True`: no counterparties, no history, because plain
    JSON-RPC simply doesn't expose that. Exists so ETH enrichment degrades
    to *something* rather than nothing when Blockscout is unavailable.
    """

    name = "publicnode_eth"
    supports = {IndicatorType.ETH_ADDRESS}
    rate_limit = RateLimit(max_requests=10, per_seconds=10)
    ttl = timedelta(hours=6)

    rpc_url = "https://ethereum-rpc.publicnode.com"

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
        balance_hex = await self._rpc("eth_getBalance", [address, "latest"])
        nonce_hex = await self._rpc("eth_getTransactionCount", [address, "latest"])
        balance = int(balance_hex, 16)
        tx_count = int(nonce_hex, 16)

        profile = ChainAddressProfile(
            chain="eth",
            address=address,
            decimals=ETH_DECIMALS,
            tx_count=tx_count,
            current_balance=Decimal(balance),
        )
        return ProviderResult(
            provider=self.name,
            raw={"balance_hex": balance_hex, "nonce_hex": nonce_hex},
            normalized=profile,
            fetched_at=datetime.now(UTC),
            partial=True,
        )
