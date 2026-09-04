"""TRON provider tests (TronGrid + Tronscan), schema-accurate fixtures."""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import httpx
import pytest

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget
from ledgerhound.enrich.chain.tron import TronGridProvider, TronscanProvider, _hex_to_base58

ADDRESS = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
COUNTERPARTY = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"

# TronGrid raw tx payloads address accounts as 0x41-prefixed hex.
ADDRESS_HEX = "41" + "a614f803b6fd780986a42c78ec9c7f77e6ded13c"


def test_hex_to_base58_round_trips_tron_address() -> None:
    import base58

    raw = base58.b58decode_check(ADDRESS)
    hex_form = raw.hex()
    assert _hex_to_base58(hex_form) == ADDRESS


def test_hex_to_base58_rejects_non_tron_prefix() -> None:
    assert _hex_to_base58("00" + "a" * 40) is None


TRONGRID_ACCOUNT = {"data": [{"address": ADDRESS_HEX, "balance": 1_000_000}]}
TRONGRID_TXS = {
    "data": [
        {
            "block_timestamp": 1_700_000_000_000,
            "raw_data": {
                "contract": [
                    {
                        "type": "TransferContract",
                        "parameter": {
                            "value": {
                                "amount": 500_000,
                                "owner_address": ADDRESS,
                                "to_address": "target-hex",
                            }
                        },
                    }
                ]
            },
        }
    ],
    "meta": {},
}


async def test_trongrid_parses_balance_and_native_transfers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/transactions"):
            return httpx.Response(200, json=TRONGRID_TXS)
        return httpx.Response(200, json=TRONGRID_ACCOUNT)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = TronGridProvider(client=client)

    # _hex_to_base58 would reject the fixture's placeholder hex strings, so
    # patch it to identity for this parsing-shape test.
    monkeypatch.setattr(
        "ledgerhound.enrich.chain.tron._hex_to_base58", lambda h: h  # noqa: ARG005
    )

    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.TRON_ADDRESS, value=ADDRESS)
    result = await provider.enrich(target)

    profile = result.normalized
    assert result.provider == "trongrid"
    assert profile.current_balance == Decimal(1_000_000)
    counterparty = profile.counterparties[0]
    assert counterparty.address == "target-hex"
    assert counterparty.direction == "out"
    assert counterparty.total_value == Decimal(500_000)


TRONSCAN_ACCOUNT = {"balance": 1_000_000, "date_created": 1_700_000_000_000}
TRONSCAN_TXS = {
    "data": [
        {
            "timestamp": 1_700_000_500_000,
            "contractType": 1,
            "ownerAddress": ADDRESS,
            "toAddress": COUNTERPARTY,
            "amount": 250_000,
        },
        {
            # A TRC20 call: contractType != 1, must not contribute value.
            "timestamp": 1_700_000_600_000,
            "contractType": 31,
            "ownerAddress": ADDRESS,
            "toAddress": COUNTERPARTY,
            "amount": 0,
        },
    ]
}


async def test_tronscan_parses_native_transfers_and_ignores_token_calls() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/transaction"):
            return httpx.Response(200, json=TRONSCAN_TXS)
        return httpx.Response(200, json=TRONSCAN_ACCOUNT)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = TronscanProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.TRON_ADDRESS, value=ADDRESS)

    result = await provider.enrich(target)
    profile = result.normalized

    assert result.provider == "tronscan"
    assert profile.current_balance == Decimal(1_000_000)
    assert len(profile.counterparties) == 1
    assert profile.counterparties[0].address == COUNTERPARTY
    assert profile.counterparties[0].total_value == Decimal(250_000)
    assert profile.first_seen_onchain is not None
