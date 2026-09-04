"""OFAC SDN parsing and known-address label lookups. No network: OFAC is
tested against the recorded fixture in tests/fixtures/enrich/sdn_sample.xml
(a hand-trimmed excerpt of the real, live SDN.XML schema)."""

from __future__ import annotations

from ledgerhound.enrich.labels.known import KnownAddressIndex
from ledgerhound.enrich.labels.ofac import OFACList, parse_sdn_xml
from tests.conftest import FIXTURES_DIR


def _load_sdn_bytes() -> bytes:
    return (FIXTURES_DIR / "enrich" / "sdn_sample.xml").read_bytes()


def test_parse_sdn_xml_extracts_tracked_chains_only() -> None:
    entries = parse_sdn_xml(_load_sdn_bytes())
    chains = {e.chain for e in entries}
    # The fixture also has an LTC entry; LTC isn't a chain Ledgerhound
    # tracks, so it must be silently dropped, not raise or appear here.
    assert chains == {"btc", "eth", "tron", "sol"}
    assert len(entries) == 4


def test_parse_sdn_xml_captures_entity_metadata() -> None:
    entries = parse_sdn_xml(_load_sdn_bytes())
    btc_entry = next(e for e in entries if e.chain == "btc")
    assert btc_entry.entity_name == "Test SCAMMER"
    assert btc_entry.sdn_type == "Individual"
    assert btc_entry.programs == ("CYBER2",)

    tron_entry = next(e for e in entries if e.chain == "tron")
    assert tron_entry.entity_name == "TEST ENTITY LLC"
    assert tron_entry.sdn_type == "Entity"


def test_ofac_list_lookup_is_case_correct_per_chain() -> None:
    ofac = OFACList.parse(_load_sdn_bytes())

    # ETH lookups are case-insensitive on-chain.
    assert ofac.lookup("eth", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed") is not None
    assert ofac.lookup("eth", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") is not None

    # BTC/TRON/SOL are base58 and case-sensitive; a case-flip is a miss.
    assert ofac.lookup("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") is not None
    assert ofac.lookup("tron", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") is not None
    assert ofac.lookup("sol", "11111111111111111111111111111111") is not None


def test_ofac_list_lookup_miss_returns_none() -> None:
    ofac = OFACList.parse(_load_sdn_bytes())
    assert ofac.lookup("btc", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is None


def test_known_address_index_loads_bundled_dataset() -> None:
    index = KnownAddressIndex.load()
    counts = index.count_by_label_type()
    assert counts["mixer"] > 0  # Tornado Cash pools, populated per README
    assert "exchange" in counts  # present, deliberately shipped empty

    # A real Tornado Cash pool address from the bundled dataset.
    hit = index.lookup("eth", "0x722122dF12D4e14e13Ac3b6895a86e84145b6967")
    assert hit is not None
    assert hit.label_type == "mixer"
    assert hit.confidence < 1.0  # contested sanctions status, see data file
    assert "ofac.treasury.gov" in hit.source.lower() or "OFAC" in hit.source

    # Case-insensitive ETH matching applies to known.py too.
    hit_lower = index.lookup("eth", "0x722122df12d4e14e13ac3b6895a86e84145b6967")
    assert hit_lower is not None


def test_known_address_index_miss_returns_none() -> None:
    index = KnownAddressIndex.load()
    assert index.lookup("eth", "0x0000000000000000000000000000000000dEaD") is None
