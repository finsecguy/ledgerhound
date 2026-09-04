"""Checksum/validation tests for each chain's address extractor, plus URL/
domain/IP/telegram-handle edge cases. All values below are well-known
public test vectors or hand-verified against reference implementations."""

from __future__ import annotations

from ledgerhound.db.models import IndicatorType
from ledgerhound.extract.indicators import (
    extract_from_text,
    validate_btc_bech32,
    validate_btc_legacy,
    validate_eth_address,
    validate_sol_address,
    validate_tron_address,
)
from ledgerhound.extract.normalize import is_eip55_checksum_valid, to_eip55

# --- BTC legacy (base58check) -----------------------------------------------


def test_btc_legacy_valid_p2pkh() -> None:
    # Genesis block coinbase address.
    assert validate_btc_legacy("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    )


def test_btc_legacy_valid_p2sh() -> None:
    assert validate_btc_legacy("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == (
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    )


def test_btc_legacy_bad_checksum_rejected() -> None:
    # Last character corrupted -> checksum must fail.
    assert validate_btc_legacy("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb") is None


def test_btc_legacy_bad_charset_rejected() -> None:
    # Contains '0' which base58 excludes.
    assert validate_btc_legacy("10A1zP1eP5QGefi2DMPTfTL5SLmv7Divf") is None


# --- BTC bech32 (BIP-173) ---------------------------------------------------


def test_btc_bech32_valid() -> None:
    addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert validate_btc_bech32(addr) == addr


def test_btc_bech32_mixed_case_still_valid_when_canonicalized() -> None:
    # BIP-173 test vector, uppercase form.
    addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
    assert validate_btc_bech32(addr) == addr.lower()


def test_btc_bech32_bad_checksum_rejected() -> None:
    corrupted = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"
    assert validate_btc_bech32(corrupted) is None


def test_btc_bech32_mixed_case_within_string_rejected() -> None:
    # BIP-173 explicitly forbids mixed upper/lower within one string.
    mixed = "bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert validate_btc_bech32(mixed) is None


# --- ETH / EIP-55 ------------------------------------------------------------


def test_eth_eip55_known_good_checksums() -> None:
    # From the EIP-55 spec examples.
    good = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]
    for addr in good:
        assert validate_eth_address(addr) == addr
        assert is_eip55_checksum_valid(addr)


def test_eth_eip55_corrupted_checksum_rejected() -> None:
    # Flip the case of one character in an otherwise-good checksum address.
    good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    corrupted = good[:3] + good[3].swapcase() + good[4:]
    assert corrupted != good
    assert validate_eth_address(corrupted) is None


def test_eth_all_lowercase_skips_checksum_and_canonicalizes() -> None:
    lower = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
    result = validate_eth_address(lower)
    assert result == to_eip55(lower)
    assert result == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def test_eth_all_uppercase_skips_checksum_and_canonicalizes() -> None:
    upper = "0x" + "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".upper()
    result = validate_eth_address(upper)
    assert result == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


# --- TRON --------------------------------------------------------------------


def test_tron_valid_address() -> None:
    addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert validate_tron_address(addr) == addr


def test_tron_bad_checksum_rejected() -> None:
    assert validate_tron_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6x") is None


def test_tron_wrong_prefix_byte_rejected() -> None:
    # Valid base58check but not a TRON (0x41-prefixed) payload: BTC mainnet addr.
    assert validate_tron_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") is None


# --- Solana --------------------------------------------------------------------


def test_sol_valid_32_byte_address() -> None:
    # Well-known System Program address, 32-byte base58 payload.
    addr = "11111111111111111111111111111111"
    assert validate_sol_address(addr) == addr


def test_sol_wrong_length_rejected() -> None:
    # A real 20-byte ETH-style payload address won't decode to 32 bytes.
    assert validate_sol_address("11111111111111111111111") is None


def test_sol_invalid_base58_rejected() -> None:
    # '0', 'O', 'I', 'l' are excluded from the base58 alphabet.
    assert validate_sol_address("0" * 32) is None


# --- End-to-end extraction: domains / URLs / IP rejection / telegram -------


def test_extract_domain_from_text() -> None:
    result = extract_from_text("Beware of trust-wallet-bnb.vercel.app it is a scam")
    values = {(i.type, i.value) for i in result.indicators}
    assert (IndicatorType.DOMAIN, "trust-wallet-bnb.vercel.app") in values


def test_extract_rejects_ip_literal_as_domain() -> None:
    result = extract_from_text("payload fetched from 192.168.1.10 directly")
    assert not any(i.type == IndicatorType.DOMAIN for i in result.indicators)
    assert "192.168.1.10" in result.rejected_ips


def test_extract_handles_defanged_input() -> None:
    result = extract_from_text("Phishing site: hxxps://trust-wallet-bnb[.]vercel[.]app/login")
    values = {(i.type, i.value) for i in result.indicators}
    assert (IndicatorType.URL, "https://trust-wallet-bnb.vercel.app/login") in values


def test_extract_url_strips_tracking_params() -> None:
    result = extract_from_text(
        "Click https://evil.example.com/claim?token=abc&utm_source=telegram&utm_campaign=x"
    )
    urls = [i.value for i in result.indicators if i.type == IndicatorType.URL]
    assert urls == ["https://evil.example.com/claim?token=abc"]


def test_extract_url_also_yields_its_host_as_a_domain_indicator() -> None:
    result = extract_from_text("Click https://evil.example.com/claim?token=abc")
    values = {(i.type, i.value) for i in result.indicators}
    assert (IndicatorType.URL, "https://evil.example.com/claim?token=abc") in values
    assert (IndicatorType.DOMAIN, "evil.example.com") in values


def test_extract_url_with_ip_host_does_not_yield_a_domain_indicator() -> None:
    result = extract_from_text("Payload at http://192.168.1.10:8080/i")
    assert not any(i.type == IndicatorType.DOMAIN for i in result.indicators)


def test_extract_telegram_handle() -> None:
    result = extract_from_text("Join our support @scam_support_official for help")
    values = {(i.type, i.value) for i in result.indicators}
    assert (IndicatorType.TELEGRAM_HANDLE, "@scam_support_official") in values


def test_extract_does_not_treat_email_localpart_as_telegram_handle() -> None:
    result = extract_from_text("Contact us at support@example.com for help")
    assert not any(i.type == IndicatorType.TELEGRAM_HANDLE for i in result.indicators)
