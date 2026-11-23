"""The pluggable "socket" `draft_assessment` calls to get a structured
draft out of a model.

`AssessmentLLM` is a structural `Protocol`, not a base class. Anything
with a matching `.draft(...)` method works, no subclassing required.
The one concrete implementation shipped here, `OpenAICompatibleLLM`,
speaks the OpenAI `/chat/completions` + tool-calling wire format over
plain `httpx`, which is what OpenAI itself, Azure OpenAI, Ollama, LM
Studio, Groq, Together, OpenRouter, and vLLM all implement. Pointing
`llm_base_url`/`llm_model` at a different one of those is normally
enough to switch backends with no code change. Anything that isn't
OpenAI-compatible at all (a bespoke internal API, a different vendor's
own tool-calling shape) just needs a small class of its own with the
same `.draft(...)` signature; `draft_assessment` never knows the
difference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

_TOOL_NAME = "submit_assessment"


class AssessmentLLM(Protocol):
    def draft(
        self, *, model: str, system: str, user_message: str, tool_schema: dict[str, Any]
    ) -> dict[str, Any]:
        """Call the model with a forced single tool-call turn and return
        the call's arguments as a plain dict. Schema-shaped like
        `AssessmentDraft` but not yet validated as one. `parse_and_validate`
        does that next, identically regardless of which backend produced
        the dict."""
        ...


class LLMResponseError(Exception):
    """Raised when a backend's response doesn't contain a usable tool
    call. Caught at the `draft_assessment` boundary and re-raised as a
    `DraftValidationError`, so every backend's failure mode looks the
    same to the CLI and API layers above it."""


@dataclass(slots=True)
class OpenAICompatibleLLM:
    """`api_key`/`base_url` point at whichever OpenAI-compatible provider
    or self-hosted server you want; `base_url` defaults to OpenAI's own
    API. Uses plain HTTP rather than the `openai` SDK, one fewer
    dependency, and every one of the providers this targets implements
    the same request/response shape for what drafting needs."""

    api_key: str
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 60.0
    #: Injectable so tests never hit the real network, same pattern as
    #: `assess/attack.py`'s `load_attack_dataset`. A real `httpx.Client`
    #: (or none, falling back to the plain `httpx.post` module function)
    #: is used otherwise.
    client: httpx.Client | None = None

    def draft(
        self, *, model: str, system: str, user_message: str, tool_schema: dict[str, Any]
    ) -> dict[str, Any]:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_message},
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": _TOOL_NAME,
                        "description": (
                            "Submit the completed, structured campaign assessment. "
                            "Every field is required unless the schema marks it optional."
                        ),
                        "parameters": tool_schema,
                    },
                }
            ],
            "tool_choice": {"type": "function", "function": {"name": _TOOL_NAME}},
        }
        owns_client = self.client is None
        http_client = self.client if self.client is not None else httpx.Client()
        try:
            response = http_client.post(
                f"{self.base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
        finally:
            if owns_client:
                http_client.close()
        try:
            tool_calls = data["choices"][0]["message"]["tool_calls"]
            arguments = tool_calls[0]["function"]["arguments"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMResponseError(
                f"Model response contained no usable tool call: {data!r}"
            ) from exc
        # Every OpenAI-compatible provider observed in practice returns
        # `arguments` as a JSON-encoded string, not a nested object, but
        # a couple of self-hosted servers pre-parse it, so both are
        # accepted rather than assuming.
        parsed: dict[str, Any] = (
            json.loads(arguments) if isinstance(arguments, str) else arguments
        )
        return parsed

