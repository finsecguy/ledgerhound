"""DNS enrichment: a full recursive resolver primary, DNS-over-HTTPS
fallback.

The fallback exists for a concrete, non-decorative reason: plain DNS is
UDP/TCP on port 53, which some sandboxed or corporate network
environments block outright while leaving HTTPS open. Cloudflare's DoH
JSON API answers the exact same query over plain HTTPS, so it's a real
fallback path, not just a second implementation of the same transport.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import structlog
from pydantic import BaseModel, Field
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from ledgerhound.db.models import IndicatorType
from ledgerhound.enrich.base import EnrichmentTarget, Provider, ProviderResult, RateLimit

logger = structlog.get_logger(__name__)


class DnsRecords(BaseModel):
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    nxdomain: bool = False
    #: ASN hosting the first A record, if any — clustering joins scam
    #: infrastructure on shared hosting providers via this field.
    asn: str | None = None


async def lookup_asn(ip: str) -> str | None:
    """Resolve an IPv4 address to its announcing ASN via Team Cymru's
    free DNS-based IP-to-ASN service — a reverse-octet TXT query against
    `origin.asn.cymru.com`, no API key or HTTP endpoint involved. Returns
    just the ASN number (e.g. "16509"), or None if the lookup fails."""
    octets = ip.split(".")
    if len(octets) != 4:
        return None
    query_name = f"{'.'.join(reversed(octets))}.origin.asn.cymru.com"
    try:
        answer = await dns.asyncresolver.resolve(query_name, "TXT", lifetime=5.0)
    except dns.exception.DNSException:
        return None
    for rdata in answer:
        # Format: "ASN | prefix | country | registry | date"
        text: str = rdata.to_text().strip('"')
        asn = text.split("|")[0].strip()
        if asn:
            return asn
    return None


class DnsResolverProvider(Provider):
    """Primary: a full recursive resolver via dnspython.

    Not an HTTP call, so it doesn't route through `http_request` — but it
    gets the same retry/backoff treatment via the same tenacity library,
    for the same reason: a single transient UDP timeout shouldn't fail
    the whole lookup.
    """

    name = "dns_resolver"
    supports = {IndicatorType.DOMAIN}
    rate_limit = RateLimit(max_requests=20, per_seconds=10)
    ttl = timedelta(hours=12)

    async def _resolve(self, name: str, rdtype: str) -> list[str]:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        async for attempt in AsyncRetrying(
            retry=retry_if_exception_type(dns.exception.Timeout),
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=0.5),
            reraise=True,
        ):
            with attempt:
                try:
                    answer = await resolver.resolve(name, rdtype)
                except dns.resolver.NoAnswer:
                    return []
                return [rdata.to_text().strip('"') for rdata in answer]
        return []  # unreachable; AsyncRetrying always raises or returns

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[DnsRecords]:
        domain = target.value
        try:
            a = await self._resolve(domain, "A")
        except dns.resolver.NXDOMAIN:
            records = DnsRecords(nxdomain=True)
            return ProviderResult(
                provider=self.name,
                raw={"nxdomain": True},
                normalized=records,
                fetched_at=datetime.now(UTC),
            )

        aaaa: list[str] = []
        ns: list[str] = []
        mx: list[str] = []
        txt: list[str] = []
        for rdtype, sink in (("AAAA", aaaa), ("NS", ns), ("MX", mx), ("TXT", txt)):
            try:
                sink.extend(await self._resolve(domain, rdtype))
            except dns.resolver.NXDOMAIN:
                continue  # A resolved fine; treat this as "no records of this type"

        asn = await lookup_asn(a[0]) if a else None
        records = DnsRecords(a=a, aaaa=aaaa, ns=ns, mx=mx, txt=txt, asn=asn)
        return ProviderResult(
            provider=self.name,
            raw={"A": a, "AAAA": aaaa, "NS": ns, "MX": mx, "TXT": txt, "asn": asn},
            normalized=records,
            fetched_at=datetime.now(UTC),
        )


_DOH_TYPE_CODES = {"A": 1, "AAAA": 28, "NS": 2, "MX": 15, "TXT": 16}


class CloudflareDohProvider(Provider):
    """Fallback: Cloudflare's DNS-over-HTTPS JSON API — same data, plain
    HTTPS transport, so it survives environments that block raw DNS."""

    name = "cloudflare_doh"
    supports = {IndicatorType.DOMAIN}
    rate_limit = RateLimit(max_requests=20, per_seconds=10)
    ttl = timedelta(hours=12)

    base_url = "https://cloudflare-dns.com/dns-query"

    async def _query(self, name: str, rdtype: str) -> dict[str, Any]:
        response = await self.request(
            "GET",
            self.base_url,
            params={"name": name, "type": rdtype},
            headers={"accept": "application/dns-json"},
        )
        result: dict[str, Any] = response.json()
        return result

    async def enrich(self, target: EnrichmentTarget) -> ProviderResult[DnsRecords]:
        domain = target.value
        raw: dict[str, Any] = {}

        a_result = await self._query(domain, "A")
        raw["A"] = a_result
        if a_result.get("Status") == 3:  # NXDOMAIN per RFC 8484 / draft-ietf-doh
            records = DnsRecords(nxdomain=True)
            return ProviderResult(
                provider=self.name, raw=raw, normalized=records, fetched_at=datetime.now(UTC)
            )

        def texts(payload: dict[str, Any]) -> list[str]:
            return [a["data"].strip('"') for a in payload.get("Answer", [])]

        aaaa_result = await self._query(domain, "AAAA")
        ns_result = await self._query(domain, "NS")
        mx_result = await self._query(domain, "MX")
        txt_result = await self._query(domain, "TXT")
        raw.update(AAAA=aaaa_result, NS=ns_result, MX=mx_result, TXT=txt_result)

        a_addresses = texts(a_result)
        asn = await lookup_asn(a_addresses[0]) if a_addresses else None
        records = DnsRecords(
            a=a_addresses,
            aaaa=texts(aaaa_result),
            ns=texts(ns_result),
            mx=texts(mx_result),
            txt=texts(txt_result),
            asn=asn,
        )
        raw["asn"] = asn
        return ProviderResult(
            provider=self.name, raw=raw, normalized=records, fetched_at=datetime.now(UTC)
        )
