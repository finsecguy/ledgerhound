"""Bech32 / BIP-173 decode and checksum verification.

Adapted from the BIP-173 reference implementation
(https://github.com/sipa/bech32, Pieter Wuille, MIT licensed) with type
hints added and trimmed to decode-only (Ledgerhound never needs to
*generate* addresses, only validate ones found in reports).
"""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _verify_checksum(hrp: str, data: list[int]) -> bool:
    return _polymod(_hrp_expand(hrp) + data) == 1


def bech32_decode(bech: str) -> tuple[str, list[int]] | None:
    """Validate a bech32 string's checksum and split it into (hrp, data).

    Returns None if the string is malformed or the checksum is invalid.
    Enforces BIP-173's "entirely upper or entirely lower case" rule.
    """
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        return None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    if not _verify_checksum(hrp, data):
        return None
    return hrp, data[:-6]


def _convertbits(
    data: list[int], frombits: int, tobits: int, pad: bool = True
) -> list[int] | None:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def decode_segwit_address(hrp: str, addr: str) -> tuple[int, bytes] | None:
    """Decode+validate a bech32 SegWit address. Returns (witness_version, program)."""
    decoded = bech32_decode(addr)
    if decoded is None or decoded[0] != hrp:
        return None
    _, data = decoded
    if not data:
        return None
    witness_version = data[0]
    program = _convertbits(data[1:], 5, 8, False)
    if program is None or not (2 <= len(program) <= 40):
        return None
    if witness_version > 16:
        return None
    if witness_version == 0 and len(program) not in (20, 32):
        return None
    return witness_version, bytes(program)
