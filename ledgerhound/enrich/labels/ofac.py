"""OFAC SDN list: sanctioned digital currency addresses.

Pulls the U.S. Treasury's Specially Designated Nationals list (published
as a redirect to a presigned S3 URL. `http_request`'s retry wrapper
follows it via `follow_redirects=True`), extracts every "Digital Currency
Address - <CURRENCY>" identification for the four chains Ledgerhound
tracks, and caches the raw XML locally so a scheduler run doesn't re-pull
a ~30MB file on every single indicator.

The live feed lists identifications for two dozen currencies (BCH, LTC,
DOGE, XRP, USDT, ...); anything outside {XBT, ETH, TRX, SOL} is parsed and
then discarded since Ledgerhound has no indicator type for it yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import structlog
from defusedxml import ElementTree as SafeET

from ledgerhound.enrich.base import Chain, http_request

logger = structlog.get_logger(__name__)

SDN_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML"

_CURRENCY_TO_CHAIN: dict[str, Chain] = {
    "XBT": "btc",
    "ETH": "eth",
    "TRX": "tron",
    "SOL": "sol",
}


@dataclass(frozen=True, slots=True)
class OFACEntry:
    entity_uid: str
    entity_name: str
    sdn_type: str
    programs: tuple[str, ...]
    chain: Chain
    address: str


def _local_tag(tag: str) -> str:
    """Strip the SDN XML's default namespace off an element tag."""
    return tag.rsplit("}", 1)[-1]


def parse_sdn_xml(xml_bytes: bytes) -> list[OFACEntry]:
    """Parse OFAC's SDN.XML into digital-currency-address entries.

    Deliberately hand-rolled over `defusedxml.ElementTree` rather than a
    full schema-aware parser: the SDN schema is large and we only need
    five fields per entry, all direct children of `sdnEntry`/`idList`.
    """
    root = SafeET.fromstring(xml_bytes)
    entries: list[OFACEntry] = []

    for sdn_entry in root:
        if _local_tag(sdn_entry.tag) != "sdnEntry":
            continue

        uid = ""
        last_name = ""
        first_name = ""
        sdn_type = ""
        programs: list[str] = []
        hits: list[tuple[Chain, str]] = []

        for child in sdn_entry:
            tag = _local_tag(child.tag)
            if tag == "uid":
                uid = child.text or ""
            elif tag == "lastName":
                last_name = child.text or ""
            elif tag == "firstName":
                first_name = child.text or ""
            elif tag == "sdnType":
                sdn_type = child.text or ""
            elif tag == "programList":
                programs = [
                    (prog.text or "").strip() for prog in child if _local_tag(prog.tag) == "program"
                ]
            elif tag == "idList":
                for id_elem in child:
                    if _local_tag(id_elem.tag) != "id":
                        continue
                    id_type = ""
                    id_number = ""
                    for id_field in id_elem:
                        field_tag = _local_tag(id_field.tag)
                        if field_tag == "idType":
                            id_type = id_field.text or ""
                        elif field_tag == "idNumber":
                            id_number = id_field.text or ""
                    if not id_type.startswith("Digital Currency Address - "):
                        continue
                    currency = id_type.removeprefix("Digital Currency Address - ").strip()
                    chain = _CURRENCY_TO_CHAIN.get(currency)
                    if chain is not None and id_number.strip():
                        hits.append((chain, id_number.strip()))

        entity_name = " ".join(part for part in (first_name, last_name) if part)
        for chain, address in hits:
            entries.append(
                OFACEntry(
                    entity_uid=uid,
                    entity_name=entity_name,
                    sdn_type=sdn_type,
                    programs=tuple(programs),
                    chain=chain,
                    address=address,
                )
            )

    return entries


def _normalize(chain: Chain, address: str) -> str:
    # ETH addresses are case-insensitive on-chain; everything else
    # Ledgerhound tracks (BTC/TRON base58, SOL base58) is case-sensitive.
    return address.lower() if chain == "eth" else address


class OFACList:
    """In-memory (chain, address) -> OFACEntry lookup over parsed SDN data."""

    def __init__(self, entries: list[OFACEntry]) -> None:
        self._by_key: dict[tuple[Chain, str], OFACEntry] = {
            (entry.chain, _normalize(entry.chain, entry.address)): entry for entry in entries
        }

    def lookup(self, chain: Chain, address: str) -> OFACEntry | None:
        return self._by_key.get((chain, _normalize(chain, address)))

    def __len__(self) -> int:
        return len(self._by_key)

    @classmethod
    def parse(cls, xml_bytes: bytes) -> OFACList:
        return cls(parse_sdn_xml(xml_bytes))


class OFACSource:
    """Fetches, locally caches, and periodically refreshes the SDN list."""

    name = "ofac_sdn"

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        cache_path: Path,
        ttl: timedelta = timedelta(hours=24),
    ) -> None:
        self.client = client
        self.cache_path = cache_path
        self.ttl = ttl
        self.log = logger.bind(provider=self.name)

    def _cache_age(self) -> timedelta | None:
        if not self.cache_path.exists():
            return None
        mtime = datetime.fromtimestamp(self.cache_path.stat().st_mtime, tz=UTC)
        return datetime.now(UTC) - mtime

    async def load(self, *, force_refresh: bool = False) -> OFACList:
        age = self._cache_age()
        if force_refresh or age is None or age > self.ttl:
            await self._refresh()
        return OFACList.parse(self.cache_path.read_bytes())

    async def _refresh(self) -> None:
        response = await http_request(
            self.client,
            "GET",
            SDN_URL,
            follow_redirects=True,
            timeout=60.0,
        )
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_bytes(response.content)
        self.log.info("ofac_sdn_refreshed", num_bytes=len(response.content), url=SDN_URL)

