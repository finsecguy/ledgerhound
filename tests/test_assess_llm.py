"""`OpenAICompatibleLLM`: the request it builds (tool spec, forced
tool_choice, auth header, configurable base_url) and how it parses a
response back into a plain dict, both the common case (arguments as a
JSON string) and a self-hosted server that hands back a pre-parsed
object. The real network is never touched; `httpx.MockTransport`
inspects the outgoing request and returns a canned response."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ledgerhound.assess.llm import LLMResponseError, OpenAICompatibleLLM

TOOL_SCHEMA: dict[str, Any] = {"type": "object", "properties": {"summary": {"type": "string"}}}


def _client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_draft_sends_forced_tool_choice_and_auth_header() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers["authorization"]
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "submit_assessment",
                                        "arguments": json.dumps({"summary": "ok"}),
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
        )

    llm = OpenAICompatibleLLM(
        api_key="sk-test", base_url="https://example.test/v1", client=_client(handler)
    )
    result = llm.draft(
        model="my-model", system="sys prompt", user_message="evidence here", tool_schema=TOOL_SCHEMA
    )

    assert result == {"summary": "ok"}
    assert captured["url"] == "https://example.test/v1/chat/completions"
    assert captured["auth"] == "Bearer sk-test"
    assert captured["body"]["model"] == "my-model"
    assert captured["body"]["messages"] == [
        {"role": "system", "content": "sys prompt"},
        {"role": "user", "content": "evidence here"},
    ]
    assert captured["body"]["tool_choice"] == {
        "type": "function",
        "function": {"name": "submit_assessment"},
    }
    assert captured["body"]["tools"][0]["function"]["parameters"] == TOOL_SCHEMA


def test_draft_accepts_pre_parsed_object_arguments() -> None:
    """A couple of self-hosted OpenAI-compatible servers return `arguments`
    as a nested object instead of a JSON-encoded string; both are valid."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "submit_assessment",
                                        "arguments": {"summary": "ok"},
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
        )

    llm = OpenAICompatibleLLM(api_key="sk-test", client=_client(handler))
    result = llm.draft(model="m", system="s", user_message="u", tool_schema=TOOL_SCHEMA)
    assert result == {"summary": "ok"}


def test_draft_raises_llm_response_error_when_no_tool_call_present() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "no tool call"}}]})

    llm = OpenAICompatibleLLM(api_key="sk-test", client=_client(handler))
    with pytest.raises(LLMResponseError):
        llm.draft(model="m", system="s", user_message="u", tool_schema=TOOL_SCHEMA)


def test_draft_raises_on_http_error_status() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    llm = OpenAICompatibleLLM(api_key="sk-bad", client=_client(handler))
    with pytest.raises(httpx.HTTPStatusError):
        llm.draft(model="m", system="s", user_message="u", tool_schema=TOOL_SCHEMA)

