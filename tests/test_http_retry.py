"""fetch_url retry/backoff behavior, using httpx.MockTransport (no network)."""

from __future__ import annotations

import httpx
import pytest

from ledgerhound.collect.base import fetch_url
from ledgerhound.settings import Settings


@pytest.fixture()
def fast_settings() -> Settings:
    # Real backoff would slow the test suite down for no benefit; keep the
    # multiplier tiny while still exercising the retry loop.
    return Settings(_env_file=None, http_max_attempts=3, http_backoff_seconds=0.001)  # type: ignore[call-arg]


def test_fetch_url_retries_on_server_error_then_succeeds(fast_settings: Settings) -> None:
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = fetch_url(client, "https://example.invalid/feed", settings=fast_settings)

    assert response.status_code == 200
    assert attempts["n"] == 3


def test_fetch_url_gives_up_after_max_attempts(fast_settings: Settings) -> None:
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(503)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        fetch_url(client, "https://example.invalid/feed", settings=fast_settings)

    assert attempts["n"] == fast_settings.http_max_attempts


def test_fetch_url_does_not_retry_client_errors(fast_settings: Settings) -> None:
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        fetch_url(client, "https://example.invalid/feed", settings=fast_settings)

    assert attempts["n"] == 1
