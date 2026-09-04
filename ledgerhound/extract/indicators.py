"""Indicator extraction: find candidate IOC strings and *validate* them.

Regex alone produces garbage — plenty of random-looking base58/hex strings
match an address's shape without being one. Every extractor here pairs a
regex (to find candidates) with real validation (checksum, structural, or
decode checks) before anything is accepted as an indicator.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import base58

from ledgerhound.db.models import IndicatorType
from ledgerhound.extract._bech32 import decode_segwit_address
from ledgerhound.extract.normalize import (
    canonicalize_domain,
    clean_url,
    defang,
    is_eip55_checksum_valid,
    is_valid_domain_label_set,
    refang,
    to_eip55,
)

# --- Candidate regexes -------------------------------------------------------

_BTC_LEGACY_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BECH32_RE = re.compile(r"\bbc1[ac-hj-np-z02-9]{6,87}\b", re.IGNORECASE)
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_SOL_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
_URL_RE = re.compile(r"""\bhttps?://[^\s<>"'\]\)]+""", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,24}\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_TELEGRAM_RE = re.compile(r"(?<!\w)@([A-Za-z][A-Za-z0-9_]{4,31})\b")
#: Bare IPv4 literal, e.g. found next to a domain in report text. IPv6
#: literals in report text are comparatively rare and, unlike IPv4, don't
#: collide with the domain regex's shape, so they aren't a false-positive
#: risk worth chasing here.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True, slots=True)
class ExtractedIndicator:
    type: IndicatorType
    value: str
    defanged_value: str


@dataclass(slots=True)
class ExtractionResult:
    indicators: list[ExtractedIndicator] = field(default_factory=list)
    #: Bare tokens that looked like domains but were actually IP literals —
    #: kept for visibility/logging, deliberately not stored as indicators.
    rejected_ips: list[str] = field(default_factory=list)


# --- Per-chain validators: return the canonical value, or None if invalid ---


def validate_btc_legacy(candidate: str) -> str | None:
    try:
        decoded = base58.b58decode_check(candidate)
    except ValueError:
        return None
    if len(decoded) != 21:
        return None
    version = decoded[0]
    if candidate[0] == "1" and version != 0x00:
        return None
    if candidate[0] == "3" and version != 0x05:
        return None
    return candidate


def validate_btc_bech32(candidate: str) -> str | None:
    # Pass the original (not pre-lowered) candidate through: bech32_decode's
    # mixed-case rejection only has teeth if it sees the case as-typed.
    if decode_segwit_address("bc", candidate) is None:
        return None
    return candidate.lower()


def validate_eth_address(candidate: str) -> str | None:
    hex_part = candidate[2:]
    if hex_part == hex_part.lower() or hex_part == hex_part.upper():
        # No mixed case: no checksum was encoded, so none to validate.
        # Canonicalize to EIP-55 form for consistent storage.
        return to_eip55(candidate)
    if not is_eip55_checksum_valid(candidate):
        return None
    return candidate


def validate_tron_address(candidate: str) -> str | None:
    try:
        decoded = base58.b58decode_check(candidate)
    except ValueError:
        return None
    if len(decoded) != 21 or decoded[0] != 0x41:
        return None
    return candidate


def validate_sol_address(candidate: str) -> str | None:
    try:
        decoded = base58.b58decode(candidate)
    except ValueError:
        return None
    if len(decoded) != 32:
        return None
    return candidate


def _is_ip_literal(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


# --- Sub-extractors -----------------------------------------------------


def _extract_addresses(text: str) -> Iterator[ExtractedIndicator]:
    seen: set[tuple[IndicatorType, str]] = set()

    def emit(itype: IndicatorType, value: str) -> Iterator[ExtractedIndicator]:
        key = (itype, value)
        if key in seen:
            return
        seen.add(key)
        yield ExtractedIndicator(type=itype, value=value, defanged_value=value)

    for match in _BTC_LEGACY_RE.finditer(text):
        canonical = validate_btc_legacy(match.group())
        if canonical:
            yield from emit(IndicatorType.BTC_ADDRESS, canonical)

    for match in _BTC_BECH32_RE.finditer(text):
        canonical = validate_btc_bech32(match.group())
        if canonical:
            yield from emit(IndicatorType.BTC_ADDRESS, canonical)

    for match in _ETH_RE.finditer(text):
        canonical = validate_eth_address(match.group())
        if canonical:
            yield from emit(IndicatorType.ETH_ADDRESS, canonical)

    for match in _TRON_RE.finditer(text):
        canonical = validate_tron_address(match.group())
        if canonical:
            yield from emit(IndicatorType.TRON_ADDRESS, canonical)

    for match in _SOL_RE.finditer(text):
        canonical = validate_sol_address(match.group())
        if canonical:
            yield from emit(IndicatorType.SOL_ADDRESS, canonical)


def _extract_urls_and_domains(text: str) -> tuple[list[ExtractedIndicator], list[str]]:
    indicators: list[ExtractedIndicator] = []
    rejected_ips: list[str] = []
    seen: set[tuple[IndicatorType, str]] = set()
    consumed_spans: list[tuple[int, int]] = []

    for match in _URL_RE.finditer(text):
        consumed_spans.append(match.span())
        raw_url = match.group().rstrip(".,;:!?")
        try:
            canonical = clean_url(raw_url)
        except ValueError:
            continue
        key = (IndicatorType.URL, canonical)
        if key not in seen:
            seen.add(key)
            indicators.append(
                ExtractedIndicator(
                    type=IndicatorType.URL, value=canonical, defanged_value=defang(canonical)
                )
            )

        # A URL's host is itself a first-class indicator: later milestones
        # cluster campaigns partly on shared domain infrastructure
        # (registrar/NS, certs), which only works if the domain is stored
        # independently of the specific path/query it happened to appear
        # with here.
        host = urlsplit(canonical).hostname
        if host and not _is_ip_literal(host):
            host_canonical = canonicalize_domain(host)
            if is_valid_domain_label_set(host_canonical):
                host_key = (IndicatorType.DOMAIN, host_canonical)
                if host_key not in seen:
                    seen.add(host_key)
                    indicators.append(
                        ExtractedIndicator(
                            type=IndicatorType.DOMAIN,
                            value=host_canonical,
                            defanged_value=defang(host_canonical),
                        )
                    )

    ip_spans: list[tuple[int, int]] = []
    seen_ips: set[str] = set()
    for match in _IPV4_RE.finditer(text):
        candidate = match.group()
        if _is_ip_literal(candidate):
            ip_spans.append(match.span())
            if candidate not in seen_ips:
                seen_ips.add(candidate)
                rejected_ips.append(candidate)

    for match in _DOMAIN_RE.finditer(text):
        start, end = match.span()
        if any(cs <= start and end <= ce for cs, ce in consumed_spans):
            continue  # already covered by a full URL match
        if any(cs <= start and end <= ce for cs, ce in ip_spans):
            continue  # bare IP literal, not a domain — tracked in rejected_ips above
        candidate = match.group()
        canonical = canonicalize_domain(candidate)
        if not is_valid_domain_label_set(canonical):
            continue
        key = (IndicatorType.DOMAIN, canonical)
        if key not in seen:
            seen.add(key)
            indicators.append(
                ExtractedIndicator(
                    type=IndicatorType.DOMAIN, value=canonical, defanged_value=defang(canonical)
                )
            )

    return indicators, rejected_ips


def _extract_telegram_handles(text: str) -> Iterator[ExtractedIndicator]:
    # Mask email addresses first so a handle regex never mistakes the
    # domain half of `user@example.com` (or captures a bare local-part)
    # for a Telegram handle.
    masked = _EMAIL_RE.sub(lambda m: "#" * len(m.group()), text)
    seen: set[str] = set()
    for match in _TELEGRAM_RE.finditer(masked):
        handle = match.group(1)
        canonical = "@" + handle.lower()
        if canonical in seen:
            continue
        seen.add(canonical)
        yield ExtractedIndicator(
            type=IndicatorType.TELEGRAM_HANDLE, value=canonical, defanged_value=canonical
        )


# --- Public API ---------------------------------------------------------


def extract_from_text(text: str) -> ExtractionResult:
    """Extract every validated indicator found in a single string."""
    text = refang(text)
    result = ExtractionResult()
    result.indicators.extend(_extract_addresses(text))
    url_domain_indicators, rejected_ips = _extract_urls_and_domains(text)
    result.indicators.extend(url_domain_indicators)
    result.rejected_ips.extend(rejected_ips)
    result.indicators.extend(_extract_telegram_handles(text))
    return result


def _iter_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        if value:
            yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _iter_strings(v)


def extract_from_payload(payload: Any) -> ExtractionResult:
    """Extract every validated indicator found anywhere in a JSON payload."""
    merged = ExtractionResult()
    seen: set[tuple[IndicatorType, str]] = set()
    for text in _iter_strings(payload):
        partial = extract_from_text(text)
        for indicator in partial.indicators:
            key = (indicator.type, indicator.value)
            if key not in seen:
                seen.add(key)
                merged.indicators.append(indicator)
        merged.rejected_ips.extend(partial.rejected_ips)
    return merged
