"""Infra provider tests: DNS (resolver + DoH fallback), RDAP (IANA
bootstrap + rdap.org fallback), certs (crt.sh), HTTP fingerprint.
No network: dnspython's resolver is monkeypatched directly (it isn't an
HTTP call), everything else goes through httpx.MockTransport."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import dns.rdatatype
import dns.resolver
import httpx
import pytest

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget, ProviderError
from ledgerhound.enrich.infra.certs import CrtShProvider, _parse_crtsh
from ledgerhound.enrich.infra.dns import CloudflareDohProvider, DnsResolverProvider
from ledgerhound.enrich.infra.http import HttpFingerprintProvider
from ledgerhound.enrich.infra.whois import (
    IanaBootstrapRdapProvider,
    RdapOrgProvider,
    parse_rdap,
)

DOMAIN = "evil.example.com"


# --- DNS ---------------------------------------------------------------


class _FakeAnswer:
    def __init__(self, texts: list[str]) -> None:
        self._texts = texts

    def __iter__(self):  # type: ignore[no-untyped-def]
        for text in self._texts:
            yield type("Rdata", (), {"to_text": lambda self, t=text: t})()


async def test_dns_resolver_provider_returns_all_record_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = {
        "A": _FakeAnswer(["1.2.3.4"]),
        "AAAA": _FakeAnswer([]),
        "NS": _FakeAnswer(["ns1.evil.example.com."]),
        "MX": _FakeAnswer([]),
        "TXT": _FakeAnswer(['"v=spf1 -all"']),
    }

    class FakeResolver:
        timeout = 5.0
        lifetime = 5.0

        async def resolve(self, name: str, rdtype: str):  # type: ignore[no-untyped-def]
            answer = answers.get(rdtype)
            if answer is None or not list(answer):
                raise dns.resolver.NoAnswer()
            return answer

    monkeypatch.setattr("dns.asyncresolver.Resolver", FakeResolver)
    monkeypatch.setattr(
        "ledgerhound.enrich.infra.dns.lookup_asn", lambda ip: _async_return("13335")
    )

    provider = DnsResolverProvider(client=httpx.AsyncClient())
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value=DOMAIN)
    result = await provider.enrich(target)

    assert result.normalized.a == ["1.2.3.4"]
    assert result.normalized.ns == ["ns1.evil.example.com."]
    assert result.normalized.txt == ["v=spf1 -all"]
    assert result.normalized.nxdomain is False
    assert result.normalized.asn == "13335"


async def _async_return(value: object) -> object:
    return value


async def test_dns_resolver_provider_handles_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        timeout = 5.0
        lifetime = 5.0

        async def resolve(self, name: str, rdtype: str):  # type: ignore[no-untyped-def]
            raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr("dns.asyncresolver.Resolver", FakeResolver)
    provider = DnsResolverProvider(client=httpx.AsyncClient())
    target = EnrichmentTarget(
        indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="doesnotexist.example"
    )
    result = await provider.enrich(target)
    assert result.normalized.nxdomain is True


async def test_cloudflare_doh_parses_records_and_nxdomain() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        rdtype = request.url.params.get("type")
        if rdtype == "A":
            return httpx.Response(
                200,
                json={
                    "Status": 0,
                    "Answer": [{"name": DOMAIN, "type": 1, "TTL": 300, "data": "1.2.3.4"}],
                },
            )
        return httpx.Response(200, json={"Status": 0, "Answer": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = CloudflareDohProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value=DOMAIN)
    result = await provider.enrich(target)
    assert result.normalized.a == ["1.2.3.4"]

    def nx_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Status": 3, "Answer": []})

    nx_client = httpx.AsyncClient(transport=httpx.MockTransport(nx_handler))
    nx_result = await CloudflareDohProvider(client=nx_client).enrich(target)
    assert nx_result.normalized.nxdomain is True


# --- RDAP ---------------------------------------------------------------

RDAP_PAYLOAD = {
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Evil Registrar Inc"]]],
        },
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Redacted for Privacy"]]],
        },
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2024-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
    ],
    "status": ["client transfer prohibited"],
}


def test_parse_rdap_extracts_registrar_dates_and_redaction() -> None:
    profile = parse_rdap(RDAP_PAYLOAD)
    assert profile.registrar == "Evil Registrar Inc"
    assert profile.created_at == datetime.fromisoformat("2024-01-01T00:00:00+00:00")
    assert profile.expires_at == datetime.fromisoformat("2030-01-01T00:00:00+00:00")
    assert profile.registrant_country is None
    assert profile.redacted is True
    assert profile.status == ["client transfer prohibited"]


async def test_iana_bootstrap_rdap_provider_resolves_via_bootstrap_file() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rdap/dns.json":
            return httpx.Response(
                200, json={"services": [[["com"], ["https://rdap.example-registry.com/"]]]}
            )
        if "example-registry.com" in request.url.host:
            return httpx.Response(200, json=RDAP_PAYLOAD)
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = IanaBootstrapRdapProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="evil.com")
    result = await provider.enrich(target)
    assert result.normalized.registrar == "Evil Registrar Inc"


async def test_iana_bootstrap_rdap_provider_raises_for_unknown_tld() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"services": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = IanaBootstrapRdapProvider(client=client)
    target = EnrichmentTarget(
        indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="evil.nonexistenttld"
    )
    with pytest.raises(ProviderError):
        await provider.enrich(target)


async def test_rdap_org_provider_parses_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=RDAP_PAYLOAD)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = RdapOrgProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="evil.com")
    result = await provider.enrich(target)
    assert result.normalized.registrar == "Evil Registrar Inc"


# --- Certs ---------------------------------------------------------------

CRTSH_ENTRIES = [
    {
        "serial_number": "abc123",
        "issuer_name": "Let's Encrypt",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "name_value": "*.evil.example.com\nevil.example.com",
    },
    {
        # Same cert logged to a second CT log: same serial+issuer, must dedupe.
        "serial_number": "abc123",
        "issuer_name": "Let's Encrypt",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "name_value": "*.evil.example.com\nevil.example.com",
    },
]


def test_parse_crtsh_dedupes_same_cert_across_logs() -> None:
    history = _parse_crtsh(CRTSH_ENTRIES)
    sans = {c.san for c in history.certs}
    assert sans == {"*.evil.example.com", "evil.example.com"}
    assert len(history.certs) == 2  # not 4: the duplicate log entry is dropped


async def test_crtsh_provider_raises_on_non_json_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>rate limited</html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = CrtShProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value=DOMAIN)
    with pytest.raises(ProviderError):
        await provider.enrich(target)


# --- HTTP fingerprint ------------------------------------------------------


async def test_http_fingerprint_reachable_site() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/favicon.ico":
            return httpx.Response(200, content=b"icon-bytes")
        return httpx.Response(
            200,
            headers={"server": "nginx"},
            content=b"<html><head><title>Evil Site</title></head></html>",
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HttpFingerprintProvider(client=client)
    target = EnrichmentTarget(indicator_id=uuid4(), type=IndicatorType.DOMAIN, value=DOMAIN)
    result = await provider.enrich(target)

    assert result.normalized.reachable is True
    assert result.normalized.status == 200
    assert result.normalized.server_header == "nginx"
    assert result.normalized.title == "Evil Site"
    assert result.normalized.body_hash is not None
    assert result.normalized.favicon_hash is not None


async def test_http_fingerprint_dead_host_is_a_valid_result_not_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HttpFingerprintProvider(client=client)
    target = EnrichmentTarget(
        indicator_id=uuid4(), type=IndicatorType.DOMAIN, value="dead.example"
    )
    result = await provider.enrich(target)  # must not raise

    assert result.normalized.reachable is False
    assert result.normalized.unreachable_reason == "connection_error"
