"""Registry of versioned assessment-drafting prompt templates.

Every version lives in its own module (`v1.py`, a future `v2.py`, ...);
this registry is the only place `drafter.py` reaches into to resolve one
by name, so `Assessment.prompt_version` always identifies a real,
still-importable template.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ledgerhound.assess.evidence import EvidencePack
from ledgerhound.assess.prompts import v1


@dataclass(frozen=True, slots=True)
class PromptTemplate:
    version: str
    system: str
    build_user_message: Callable[[EvidencePack], str]


_TEMPLATES: dict[str, PromptTemplate] = {
    v1.VERSION: PromptTemplate(
        version=v1.VERSION, system=v1.SYSTEM_PROMPT, build_user_message=v1.build_user_message
    ),
}

LATEST_PROMPT_VERSION = v1.VERSION


def get_prompt(version: str) -> PromptTemplate:
    try:
        return _TEMPLATES[version]
    except KeyError as exc:
        raise KeyError(f"Unknown prompt version {version!r}. Known: {sorted(_TEMPLATES)}") from exc


__all__ = ["LATEST_PROMPT_VERSION", "PromptTemplate", "get_prompt"]
