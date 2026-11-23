"""Bitcoin address enrichment: mempool.space primary, blockstream.info
fallback. Both are Esplora-API deployments with byte-for-byte identical
response shapes, which makes this the cleanest possible fallback pair
losing mempool.space costs nothing but hostname.

Esplora's `/address/{addr}/txs` endpoint returns only the most recent
page (up to 25-50 confirmed/mempool txs) with no way to jump straight to
an address's *first* transaction; getting there requires paginating
backward via `/address/{addr}/txs/chain/{last_seen_txid}`. For a
low-activity scam address (the common case here) a handful of pages
covers full history. For a high-activity address, chasing every page
would mean thousands of requests, so this is bounded to a small number
of pages, and `first_seen_onchain`/counterparty totals are marked
`partial=True` whenever the address has more transactions than the pages
fetched actually covered.
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

BTC_DECIMALS = 8
_MAX_PAGES = 3


class _EsploraCounterpartyAgg:
    def __init__(self) -> None:
        self._agg: dict[tuple[str, str], list[Any]] = {}

    def add(self, address: str, direction: str, value: int) -> None:
        key = (address, direction)
        if key not in self._agg:
            self._agg[key] = [0, 0]
        self._agg[key][0] += 1
        self._agg[key][1] += value

    def to_counterparties(self) -> list[Counterparty]:
        return [
            Counterparty(
                address=address, direction=direction, tx_count=count, total_value=Decimal(value)
            )
            for (address, direction), (count, value) in sorted(
                self._agg.items(), key=lambda kv: kv[1][1], reverse=True
            )
        ]


def _parse_txs(address: str, txs: list[dict[str, Any]], agg: _EsploraCounterpartyAgg) -> None:
    for tx in txs:
        for vin in tx.get("vin", []):
            prevout = vin.get("prevout") or {}
            if prevout.get("scriptpubkey_address") == address:
                for vout in tx.get("vout", []):
                    out_addr = vout.get("scriptpubkey_address")
                    if out_addr and out_addr != address:
                        agg.add(out_addr, "out", int(vout.get("value", 0)))
        for vout in tx.get("vout", []):
            if vout.get("scriptpubkey_address") == address:
                value = int(vout.get("value", 0))
                senders = [
                    (vin.get("prevout") or {}).get("scriptpubkey_address")
                    for vin in tx.get("vin", [])
                ]
                valid_senders = [s for s in senders if s and s != address]
                if valid_senders:
                    # A UTXO tx can have multiple inputs; without per-input
                    # value attribution we credit the full received value to
                    # each distinct sender rather than guess a split.
                    for sender in set(valid_senders):
                        agg.add(str(sender), "in", value)


class _EsploraProvider(Provider):
    supports = {IndicatorType.BTC_ADDRESS}
    ttl = timedelta(hours=6)

    def __init__(self, *, base_url: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.base_url = base_url

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
        address = target.value
        stats_resp = await self.request("GET", f"{self.base_url}/address/{address}")
        stats = stats_resp.json()

        chain_stats = stats.get("chain_stats", {})
        mempool_stats = stats.get("mempool_stats", {})
        total_received = int(chain_stats.get("funded_txo_sum", 0))
        total_sent = int(chain_stats.get("spent_txo_sum", 0))
        tx_count = int(chain_stats.get("tx_count", 0)) + int(mempool_stats.get("tx_count", 0))

        agg = _EsploraCounterpartyAgg()
        all_txs: list[dict[str, Any]] = []
        last_txid: str | None = None
        for _ in range(_MAX_PAGES):
            url = f"{self.base_url}/address/{address}/txs"
            if last_txid:
                url = f"{self.base_url}/address/{address}/txs/chain/{last_txid}"
            page_resp = await self.request("GET", url)
            page = page_resp.json()
            if not page:
                break
            all_txs.extend(page)
            last_txid = page[-1].get("txid")
            if len(page) < 25:
                break  # short page: this was the last one

        _parse_txs(address, all_txs, agg)

        block_times = [
            tx["status"]["block_time"]
            for tx in all_txs
            if tx.get("status", {}).get("confirmed") and tx["status"].get("block_time")
        ]
        first_seen = datetime.fromtimestamp(min(block_times), tz=UTC) if block_times else None
        last_seen = datetime.fromtimestamp(max(block_times), tz=UTC) if block_times else None

        # We only ever fetched a bounded window of the most recent pages;
        # if the address has more confirmed txs than we walked, our
        # counterparty aggregation and (especially) first_seen are a
        # lower bound on true history, not the full picture.
        partial = tx_count > len(all_txs)

        profile = ChainAddressProfile(
            chain="btc",
            address=address,
            decimals=BTC_DECIMALS,
            first_seen_onchain=first_seen,
            last_seen_onchain=last_seen,
            tx_count=tx_count,
            total_received=Decimal(total_received),
            total_sent=Decimal(total_sent),
            current_balance=Decimal(total_received - total_sent),
            counterparties=agg.to_counterparties(),
        )
        return ProviderResult(
            provider=self.name,
            raw={"address": stats, "txs": all_txs},
            normalized=profile,
            fetched_at=datetime.now(UTC),
            partial=partial,
        )


class MempoolSpaceProvider(_EsploraProvider):
    name = "mempool_space"
    rate_limit = RateLimit(max_requests=10, per_seconds=10)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(base_url="https://mempool.space/api", **kwargs)


class BlockstreamProvider(_EsploraProvider):
    name = "blockstream"
    rate_limit = RateLimit(max_requests=10, per_seconds=10)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(base_url="https://blockstream.info/api", **kwargs)

