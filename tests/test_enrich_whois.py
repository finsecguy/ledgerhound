"""RDAP (primary) + real WHOIS (fallback) tests for domain registration
data. Fixtures in tests/fixtures/enrich/: a fully-populated RDAP response,
a GDPR-redacted one, an RFC 9537 redacted one, an RDAP 404, a bootstrap
file missing a TLD entry, and a real captured raw .sk WHOIS response.
No network: httpx.MockTransport for RDAP, a monkeypatched `_whois_query`
for the port-43 path (there's no HTTP transport to intercept there)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget, ProviderError
from ledgerhound.enrich.infra import whois as whois_module
from ledgerhound.enrich.infra.whois import (
    IanaBootstrapRdapProvider,
    RdapOrgProvider,
    WhoisProvider,
    _parse_generic_whois,
    _parse_sk_whois,
    parse_rdap,
)
from ledgerhound.enrich.registry import ProviderRegistry
from tests.conftest import FIXTURES_DIR

ENRICH_FIXTURES = FIXTURES_DIR / "enrich"


def _load_json(name: str) -> dict:
    return json.loads((ENRICH_FIXTURES / name).read_text(encoding="utf-8"))


def _load_text(name: str) -> str:
    return (ENRICH_FIXTURES / name).read_text(encoding="utf-8")


# --- RDAP JSON parsing: the six requested scenarios -------------------


def test_rdap_fully_populated_response() -> None:
    profile = parse_rdap(_load_json("rdap_full.json"))

    assert profile.registered is True
    assert profile.registrar == "Example Registrar Inc"
    assert profile.created_at == datetime(2018, 3, 14, tzinfo=UTC)
    assert profile.updated_at == datetime(2026, 6, 1, 12, 30, tzinfo=UTC)
    assert profile.expires_at == datetime(2028, 3, 14, tzinfo=UTC)
    assert profile.nameservers == ["ns1.example-corp.example", "ns2.example-corp.example"]
    assert profile.status == ["client transfer prohibited", "client update prohibited"]
    assert profile.registrant_country == "US"
    assert profile.redacted is False


def test_rdap_gdpr_redacted_response() -> None:
    profile = parse_rdap(_load_json("rdap_gdpr_redacted.json"))

    assert profile.redacted is True
    assert profile.registrant_country is None
    # Redaction doesn't hide everything: registrar/dates/nameservers are
    # still real data and still get stored.
    assert profile.registrar == "Cheap Registrar LLC"
    assert profile.nameservers


def test_rdap_rfc9537_redacted_response() -> None:
    payload = _load_json("rdap_rfc9537_redacted.json")
    profile = parse_rdap(payload)

    # This fixture's registrant fn is an empty string, not one of the
    # known marker phrases — only the RFC 9537 `redacted` array proves
    # this is redaction rather than genuinely absent data.
    assert "redacted" in payload
    assert profile.redacted is True
    assert profile.registrar == "Modern Registrar Inc"


async def test_rdap_404_is_a_valid_registered_false_result_not_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json=_load_json("rdap_404.json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = RdapOrgProvider(client=client)
    target = EnrichmentTarget(
        indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="unregistered.example"
    )

    result = await provider.enrich(target)  # must not raise

    assert result.normalized.registered is False
    assert result.provider == "rdap_org"


async def test_rdap_org_no_service_404_is_a_failure_not_unregistered() -> None:
    """rdap.org 404s for two different reasons distinguishable only by
    response body: a real "not registered" (usually empty body) versus
    "I have no RDAP server for this TLD at all" (this exact title,
    verified live against .ch and .sk). The second must raise so the
    registry falls through to WHOIS — it must NOT be recorded as
    registered=False, which would be actively wrong."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json=_load_json("rdap_org_no_service.json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = RdapOrgProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="example.sk")

    with pytest.raises(ProviderError):
        await provider.enrich(target)


async def test_rdap_429_is_retried_not_treated_as_not_registered() -> None:
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] < 2:
            return httpx.Response(429)
        return httpx.Response(200, json=_load_json("rdap_full.json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = RdapOrgProvider(client=client)

    # Call the shared fetch helper directly with a tiny backoff so this
    # test doesn't wait out tenacity's real default exponential delay.
    result = await whois_module._fetch_rdap(
        provider, "https://rdap.org/domain/example.com", backoff_seconds=0.001
    )

    assert attempts["n"] == 2
    assert result.normalized.registered is True


async def test_bootstrap_missing_tld_falls_through_registry_to_whois(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """The bootstrap fixture has no entry for `ch` — IanaBootstrapRdapProvider
    must raise (not crash, not silently return empty data), and the
    registry must fall through to the WHOIS provider next in the chain."""
    bootstrap_text = (ENRICH_FIXTURES / "rdap_bootstrap_no_ch.json").read_text()

    def rdap_iana_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=bootstrap_text)

    def rdap_org_handler(request: httpx.Request) -> httpx.Response:
        # A real failure (not a 404 "not registered", which is now a
        # valid result) — rdap.org's own resolution is having trouble.
        return httpx.Response(500)

    rdap_client = httpx.AsyncClient(transport=httpx.MockTransport(rdap_iana_handler))
    rdap_org_client = httpx.AsyncClient(transport=httpx.MockTransport(rdap_org_handler))

    iana_provider = IanaBootstrapRdapProvider(
        client=rdap_client, cache_path=tmp_path / "bootstrap.json"
    )
    rdap_org_provider = RdapOrgProvider(client=rdap_org_client)
    # Speed the 500-triggered retries up so this test doesn't eat tenacity's
    # real exponential backoff.
    original_request = rdap_org_provider.request

    async def fast_request(method, url, **kwargs):  # noqa: ANN001, ANN201
        kwargs.setdefault("backoff_seconds", 0.001)
        return await original_request(method, url, **kwargs)

    monkeypatch.setattr(rdap_org_provider, "request", fast_request)

    async def fake_resolve_whois_server(tld, *, cache, timeout=10.0):  # noqa: ANN001, ARG001
        return "whois.fake-registry.example"

    async def fake_whois_query(host, query, *, timeout=10.0):  # noqa: ANN001, ARG001
        return _load_text("whois_sk_raw.txt")

    monkeypatch.setattr(whois_module, "_resolve_whois_server", fake_resolve_whois_server)
    monkeypatch.setattr(whois_module, "_whois_query", fake_whois_query)
    whois_provider = WhoisProvider(client=httpx.AsyncClient())

    registry = ProviderRegistry(
        {"domain_rdap": [iana_provider, rdap_org_provider, whois_provider]}
    )
    target = EnrichmentTarget(
        indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="urlhaus.abuse.ch"
    )

    result = await registry.enrich(target, "domain_rdap")

    # This is a .ch domain, so the .sk-specific parser correctly does NOT
    # apply here — the generic parser handles it (best-effort; some
    # sk-specific field labels like "Authorised Registrar" won't match
    # generic patterns, which is exactly why partial=True below).
    assert result.provider == "whois"
    assert result.normalized.registered is True
    assert result.normalized.created_at == datetime(2003, 9, 30, tzinfo=UTC)
    assert result.normalized.nameservers == [
        "ns1.nic.sk", "ns2.nic.sk", "ns3.nic.sk", "ns4.nic.sk",
    ]
    assert result.partial is True

    health = {row["provider"]: row for row in registry.health_snapshot()}
    assert health["rdap_iana"]["consecutive_failures"] == 1
    assert health["rdap_org"]["consecutive_failures"] == 1
    assert health["whois"]["healthy"] is True


# --- WHOIS parsing --------------------------------------------------------


def test_parse_sk_whois_real_captured_response() -> None:
    result = _parse_sk_whois(_load_text("whois_sk_raw.txt"))

    assert result.complete is True
    profile = result.profile
    assert profile.registered is True
    assert profile.registrar == "WEBG-0001"
    assert profile.created_at == datetime(2003, 9, 30, tzinfo=UTC)
    assert profile.updated_at == datetime(2026, 8, 31, tzinfo=UTC)
    assert profile.expires_at == datetime(2027, 9, 30, tzinfo=UTC)
    assert profile.registrant_country == "SK"
    assert profile.redacted is False
    assert profile.nameservers == ["ns1.nic.sk", "ns2.nic.sk", "ns3.nic.sk", "ns4.nic.sk"]
    assert profile.status == [
        "clientTransferProhibited",
        "clientUpdateProhibited",
        "clientDeleteProhibited",
    ]


def test_parse_generic_whois_marks_partial_when_fields_missing() -> None:
    sparse_text = "Registrar: Some Registrar\nCreation Date: 2020-01-01\n"
    result = _parse_generic_whois(sparse_text)

    assert result.complete is False  # no nameservers found
    assert result.profile.registrar == "Some Registrar"


async def test_generic_whois_parser_used_for_unmapped_tld(monkeypatch: pytest.MonkeyPatch) -> None:
    generic_text = (
        "Registrar: Generic Registrar Inc\n"
        "Creation Date: 2021-05-01\n"
        "Registry Expiry Date: 2027-05-01\n"
        "Name Server: ns1.generic.example\n"
        "Name Server: ns2.generic.example\n"
        "Domain Status: clientTransferProhibited\n"
    )

    async def fake_resolve_whois_server(tld, *, cache, timeout=10.0):  # noqa: ANN001, ARG001
        return "whois.generic-registry.example"

    async def fake_whois_query(host, query, *, timeout=10.0):  # noqa: ANN001, ARG001
        return generic_text

    monkeypatch.setattr(whois_module, "_resolve_whois_server", fake_resolve_whois_server)
    monkeypatch.setattr(whois_module, "_whois_query", fake_whois_query)

    provider = WhoisProvider(client=httpx.AsyncClient())
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="evil.xyz")

    result = await provider.enrich(target)

    assert result.partial is False
    assert result.normalized.registrar == "Generic Registrar Inc"
    assert result.normalized.nameservers == ["ns1.generic.example", "ns2.generic.example"]


async def test_whois_provider_end_to_end_uses_sk_parser_and_query_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_queries: list[tuple[str, str]] = []

    async def fake_resolve_whois_server(tld, *, cache, timeout=10.0):  # noqa: ANN001, ARG001
        assert tld == "sk"
        return "whois.sk-nic.sk"

    async def fake_whois_query(host, query, *, timeout=10.0):  # noqa: ANN001, ARG001
        seen_queries.append((host, query))
        return _load_text("whois_sk_raw.txt")

    monkeypatch.setattr(whois_module, "_resolve_whois_server", fake_resolve_whois_server)
    monkeypatch.setattr(whois_module, "_whois_query", fake_whois_query)

    provider = WhoisProvider(client=httpx.AsyncClient())
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="nic.sk")

    result = await provider.enrich(target)

    assert seen_queries == [("whois.sk-nic.sk", "domain nic.sk")]  # .sk needs the "domain " prefix
    assert result.provider == "whois"
    assert result.partial is False
    assert result.normalized.registrar == "WEBG-0001"


async def test_whois_provider_reports_not_found_as_unregistered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_resolve_whois_server(tld, *, cache, timeout=10.0):  # noqa: ANN001, ARG001
        return "whois.sk-nic.sk"

    async def fake_whois_query(host, query, *, timeout=10.0):  # noqa: ANN001, ARG001
        return "The queried object does not exist: DOMAIN NOT FOUND"

    monkeypatch.setattr(whois_module, "_resolve_whois_server", fake_resolve_whois_server)
    monkeypatch.setattr(whois_module, "_whois_query", fake_whois_query)

    provider = WhoisProvider(client=httpx.AsyncClient())
    target = EnrichmentTarget(
        indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="doesnotexist.sk"
    )

    result = await provider.enrich(target)

    assert result.normalized.registered is False


async def test_whois_provider_raises_when_no_referral_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_resolve_whois_server(tld, *, cache, timeout=10.0):  # noqa: ANN001, ARG001
        return None

    monkeypatch.setattr(whois_module, "_resolve_whois_server", fake_resolve_whois_server)

    provider = WhoisProvider(client=httpx.AsyncClient())
    target = EnrichmentTarget(
        indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="evil.nonexistenttld"
    )

    with pytest.raises(ProviderError):
        await provider.enrich(target)
