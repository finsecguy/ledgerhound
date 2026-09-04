"""Canonicalization, defanging, and refanging.

These are pure string functions with no I/O, so they're trivially unit
testable and reusable by both extraction and (eventually) reporting.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import idna
from Crypto.Hash import keccak

# --- Defang / refang --------------------------------------------------------
#
# "Defanging" makes an indicator safe to paste into chat/email/tickets
# without it becoming a clickable link or triggering a security filter.
# "Refanging" is the inverse, applied to *input* so already-defanged text
# copied out of a report still gets recognized and extracted correctly.

_REFANG_SCHEME_RE = re.compile(r"hxxp(s?)", re.IGNORECASE)
_REFANG_DOT_BRACKETS_RE = re.compile(r"[\[({]\s*dot\s*[\])}]|[\[({]\s*\.\s*[\])}]", re.IGNORECASE)
_REFANG_DOT_WORD_RE = re.compile(r"\s+dot\s+", re.IGNORECASE)
_REFANG_AT_BRACKETS_RE = re.compile(r"[\[({]\s*at\s*[\])}]", re.IGNORECASE)
_REFANG_COLON_BRACKETS_RE = re.compile(r"[\[({]\s*:\s*[\])}]")


def defang(value: str) -> str:
    """Make a domain/URL safe to display: http(s) -> hxxp(s), '.' -> '[.]'."""
    result = re.sub(r"https", "hxxps", value, flags=re.IGNORECASE)
    result = re.sub(r"http", "hxxp", result, flags=re.IGNORECASE)
    return result.replace(".", "[.]")


def refang(value: str) -> str:
    """Reverse common defanging conventions so extraction can recognize IOCs
    copied verbatim out of a report (hxxp, [.], (dot), [at], ...)."""
    result = _REFANG_SCHEME_RE.sub(lambda m: "http" + m.group(1), value)
    result = _REFANG_COLON_BRACKETS_RE.sub(":", result)
    result = _REFANG_DOT_BRACKETS_RE.sub(".", result)
    result = _REFANG_DOT_WORD_RE.sub(".", result)
    result = _REFANG_AT_BRACKETS_RE.sub("@", result)
    return result


# --- Domain canonicalization -------------------------------------------------

_TRACKING_PARAM_PREFIXES = ("utm_",)
_TRACKING_PARAM_NAMES = {
    "gclid",
    "fbclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "igshid",
    "ref",
    "ref_src",
    "spm",
    "yclid",
    "vero_id",
}


def _is_tracking_param(name: str) -> bool:
    lowered = name.lower()
    return lowered in _TRACKING_PARAM_NAMES or lowered.startswith(_TRACKING_PARAM_PREFIXES)


def canonicalize_domain(value: str) -> str:
    """Lowercase a domain and decode any punycode labels to unicode.

    Punycode <-> unicode is normalized consistently in one direction
    (unicode) so the same domain never gets stored as two different
    indicator rows depending on which form a report happened to use.
    """
    value = value.strip().lower().rstrip(".")
    labels = value.split(".")
    canonical_labels = []
    for label in labels:
        if label.startswith("xn--"):
            try:
                canonical_labels.append(idna.decode(label))
                continue
            except idna.IDNAError:
                pass
        canonical_labels.append(label)
    return ".".join(canonical_labels)


def is_valid_domain_label_set(value: str) -> bool:
    """True if every label of `value` is a structurally valid DNS/IDNA label."""
    if not value or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label:
            return False
        try:
            idna.encode(label.encode("ascii") if label.isascii() else label)
        except (idna.IDNAError, UnicodeError):
            return False
    return True


def clean_url(value: str) -> str:
    """Normalize a URL: lowercase scheme/host, strip tracking query params,
    drop the fragment. Path and remaining query values keep their case."""
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    query_pairs = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not _is_tracking_param(k)
    ]
    query_pairs.sort(key=lambda kv: kv[0])
    query = urlencode(query_pairs)
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, query, ""))


# --- Ethereum EIP-55 checksum -----------------------------------------------


def to_eip55(address: str) -> str:
    """Return the EIP-55 mixed-case checksum form of a 40-hex-char address.

    `address` may or may not have a leading "0x"; the hex portion is
    otherwise assumed already valid (40 hex chars).
    """
    hex_part = address.lower().removeprefix("0x")
    address_hash = keccak.new(data=hex_part.encode("ascii"), digest_bits=256).hexdigest()
    chars = []
    for i, ch in enumerate(hex_part):
        if ch in "0123456789":
            chars.append(ch)
        else:
            chars.append(ch.upper() if int(address_hash[i], 16) >= 8 else ch)
    return "0x" + "".join(chars)


def is_eip55_checksum_valid(address_with_0x: str) -> bool:
    """True if `address_with_0x` matches its own EIP-55 checksum form."""
    return to_eip55(address_with_0x) == address_with_0x
