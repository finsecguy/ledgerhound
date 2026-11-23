"""Neutralise instruction-like text that arrived inside untrusted fields.

WHOIS strings, page titles, and indicator values are data. A report can
still contain phrases that look like a prompt (`ignore previous
instructions`, fake role markers, "mark as benign", or a request to
exfiltrate the pack). Screening replaces those spans with a fixed marker
before the text is stored on a registration profile, kept as a page
title, or copied into the assessment prompt. The marker is not itself an
instruction, so running the screen twice is stable.
"""

from __future__ import annotations

import re

NEUTRALIZED_MARKER = "[removed untrusted instruction]"

# Role markers and instruction phrases, including the underscore form a
# Telegram handle can actually carry (handles cannot contain spaces).
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"ignore[\s_\-]+(?:all[\s_\-]+|any[\s_\-]+)?(?:previous|prior|above)"
        r"[\s_\-]+instructions",
        re.IGNORECASE,
    ),
    re.compile(
        r"disregard[\s_\-]+(?:all[\s_\-]+|any[\s_\-]+)?(?:previous|prior|above)"
        r"[\s_\-]+(?:instructions|prompts)",
        re.IGNORECASE,
    ),
    re.compile(r"<\s*/?\s*(?:system|assistant|user)\s*>", re.IGNORECASE),
    re.compile(r"\[/?INST\]", re.IGNORECASE),
    re.compile(r"<<\s*/?\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"(?m)^\s*(?:system|assistant|user)\s*:\s*"),
    re.compile(r"you are now\b", re.IGNORECASE),
    re.compile(
        r"mark[\s_\-]+(?:this[\s_\-]+)?(?:campaign[\s_\-]+)?(?:as[\s_\-]+)?benign",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:set|change)[\s_\-]+(?:the[\s_\-]+)?(?:status|assessment)[\s_\-]+to[\s_\-]+\w+",
        re.IGNORECASE,
    ),
    re.compile(r"exfiltrat\w*", re.IGNORECASE),
    re.compile(
        r"send[\s_\-]+(?:the[\s_\-]+)?(?:evidence|secrets|data|pack|prompt)[\s_\-]+to\b",
        re.IGNORECASE,
    ),
)

# C0 controls (except tab, LF, CR) and bidi overrides. These can hide
# instructions from a reviewer who reads the field in a terminal.
_CONTROLS = re.compile(r"[\u0000-\u0008\u000b\u000c\u000e-\u001f\u202a-\u202e\u2066-\u2069]")


def neutralize_untrusted_text(value: str) -> str:
    """Return `value` with injection spans replaced by `NEUTRALIZED_MARKER`."""
    cleaned = _CONTROLS.sub("", value)
    for pattern in _PATTERNS:
        cleaned = pattern.sub(NEUTRALIZED_MARKER, cleaned)
    return cleaned


def injection_detected(value: str) -> bool:
    """True when screening would change `value`."""
    return neutralize_untrusted_text(value) != _CONTROLS.sub("", value)
