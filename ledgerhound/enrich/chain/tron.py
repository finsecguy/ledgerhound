"""TRON address enrichment: TronGrid primary, Tronscan fallback.

Both cover balance, tx count, and (best-effort) native-TRX counterparties.
Counterparty/value extraction is scoped to native TRX transfers only
TRC20/TRC10 token transfers show up in an address's transaction list but
don't move native TRX value, and this milestone's `ChainAddressProfile`
has no per-token breakdown. A wallet whose activity is mostly token
transfers will show a low counterparty count relative to its tx_count;
that's `partial=True`, not a bug.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import base58

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import (
    ChainAddressProfile,
    Counterparty,
    EnrichmentTarget,
    Provider,
    ProviderResult,
    RateLimit,
)

TRON_DECIMALS = 6
_TRON_ADDRESS_PREFIX = b"\x41"


def _hex_to_base58(hex_address: str) -> str | None:
    """TronGrid's raw tx payloads address accounts as 21-byte hex (0x41
    prefix); convert to the base58check T-address form everything else in
    Ledgerhound uses."""
    try:
        raw = bytes.fromhex(hex_address)
    except ValueError:
        return None
    if not raw.startswith(_TRON_ADDRESS_PREFIX):
        return None
    encoded = base58.b58encode_check(raw)
    return encoded.decode("ascii")


class TronGridProvider(Provider):
    name = "trongrid"
    supports = {IndicatorType.TRON_ADDRESS}
    rate_limit = RateLimit(max_requests=10, per_seconds=10)
    ttl = timedelta(hours=6)

    base_url = "https://api.trongrid.io"
    _max_pages = 3

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
        address = target.value
        account_resp = await self.request("GET", f"{self.base_url}/v1/accounts/{address}")
        account_payload = account_resp.json()
        account_data = (account_payload.get("data") or [{}])[0]
        balance = int(account_data.get("balance", 0))

        all_txs: list[dict[str, Any]] = []
        fingerprint: str | None = None
        for _ in range(self._max_pages):
            url = f"{self.base_url}/v1/accounts/{address}/transactions"
            params = {"limit": 50, "only_confirmed": "true"}
            if fingerprint:
                params["fingerprint"] = fingerprint
            page_resp = await self.request("GET", url, params=params)
            page = page_resp.json()
            txs = page.get("data") or []
            all_txs.extend(txs)
            fingerprint = (page.get("meta") or {}).get("fingerprint")
            if not fingerprint or not txs:
                break

        agg: dict[tuple[str, str], list[int]] = {}
        timestamps: list[datetime] = []
        for tx in all_txs:
            block_ts = tx.get("block_timestamp")
            if block_ts:
                timestamps.append(datetime.fromtimestamp(block_ts / 1000, tz=UTC))
            for contract in (tx.get("raw_data") or {}).get("contract", []):
                if contract.get("type") != "TransferContract":
                    continue
                value_data = (contract.get("parameter") or {}).get("value") or {}
                amount = int(value_data.get("amount", 0))
                owner = _hex_to_base58(value_data.get("owner_address", ""))
                to_addr = _hex_to_base58(value_data.get("to_address", ""))
                if amount <= 0 or not owner or not to_addr:
                    continue
                if owner == address and to_addr != address:
                    key = (to_addr, "out")
                    agg.setdefault(key, [0, 0])
                    agg[key][0] += 1
                    agg[key][1] += amount
                if to_addr == address and owner != address:
                    key = (owner, "in")
                    agg.setdefault(key, [0, 0])
                    agg[key][0] += 1
                    agg[key][1] += amount

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
            chain="tron",
            address=address,
            decimals=TRON_DECIMALS,
            first_seen_onchain=min(timestamps) if timestamps else None,
            last_seen_onchain=max(timestamps) if timestamps else None,
            tx_count=len(all_txs),
            total_received=total_in,
            total_sent=total_out,
            current_balance=Decimal(balance),
            counterparties=counterparties,
        )
        return ProviderResult(
            provider=self.name,
            raw={"account": account_payload, "transactions": all_txs},
            normalized=profile,
            fetched_at=datetime.now(UTC),
            # We only ever fetched a bounded number of pages, and only
            # native TransferContract entries contribute counterparties
            # a wallet dominated by token transfers is always partial.
            partial=True,
        )


class TronscanProvider(Provider):
    name = "tronscan"
    supports = {IndicatorType.TRON_ADDRESS}
    rate_limit = RateLimit(max_requests=5, per_seconds=10)
    ttl = timedelta(hours=6)

    base_url = "https://apilist.tronscan.org/api"
    _max_pages = 2

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[ChainAddressProfile]:
        address = target.value
        account_resp = await self.request(
            "GET", f"{self.base_url}/account", params={"address": address}
        )
        account = account_resp.json()
        balance = int(account.get("balance", 0))
        date_created = account.get("date_created") or 0

        all_txs: list[dict[str, Any]] = []
        start = 0
        page_size = 50
        for _ in range(self._max_pages):
            tx_resp = await self.request(
                "GET",
                f"{self.base_url}/transaction",
                params={
                    "address": address,
                    "limit": page_size,
                    "start": start,
                    "sort": "-timestamp",
                },
            )
            page = tx_resp.json()
            txs = page.get("data") or []
            all_txs.extend(txs)
            if len(txs) < page_size:
                break
            start += page_size

        agg: dict[tuple[str, str], list[int]] = {}
        timestamps: list[datetime] = []
        for tx in all_txs:
            ts = tx.get("timestamp")
            if ts:
                timestamps.append(datetime.fromtimestamp(ts / 1000, tz=UTC))
            if tx.get("contractType") != 1:  # 1 == TransferContract (native TRX)
                continue
            amount = int(tx.get("amount", 0))
            owner = tx.get("ownerAddress")
            to_addr = tx.get("toAddress")
            if amount <= 0 or not owner or not to_addr:
                continue
            if owner == address and to_addr != address:
                key = (to_addr, "out")
                agg.setdefault(key, [0, 0])
                agg[key][0] += 1
                agg[key][1] += amount
            if to_addr == address and owner != address:
                key = (owner, "in")
                agg.setdefault(key, [0, 0])
                agg[key][0] += 1
                agg[key][1] += amount

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
            chain="tron",
            address=address,
            decimals=TRON_DECIMALS,
            first_seen_onchain=datetime.fromtimestamp(date_created / 1000, tz=UTC)
            if date_created
            else (min(timestamps) if timestamps else None),
            last_seen_onchain=max(timestamps) if timestamps else None,
            tx_count=len(all_txs),
            total_received=total_in,
            total_sent=total_out,
            current_balance=Decimal(balance),
            counterparties=counterparties,
        )
        return ProviderResult(
            provider=self.name,
            raw={"account": account, "transactions": all_txs},
            normalized=profile,
            fetched_at=datetime.now(UTC),
            partial=True,
        )

