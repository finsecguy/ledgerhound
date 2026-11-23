# Data sources

Ledgerhound collects from public scam and phishing feeds. Each source is
registered in `config/sources.yaml` with an
[Admiralty reliability grade](https://en.wikipedia.org/wiki/Admiralty_code)
(A through F). The grade describes the feed as a collection process. It is
not a score for any single indicator.

Collection is pull-based. Every fetch is stored verbatim as a `raw_report`
before parsing, so extraction can be revised without fetching again.

Adding a source means implementing `ledgerhound.collect.base.Collector`
and adding an entry to `config/sources.yaml`. The dedupe and storage path
is the same for every source.

## Configured feeds

| Source | What it publishes | Grade | Cadence |
|---|---|---|---|
| [ScamSniffer](https://github.com/scamsniffer/scam-database) | Community blocklists of malicious Web3 domains and wallet addresses, as JSON arrays | B | 60 min |
| [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) | Recent malicious URLs, CSV | B | 15 min |
| [CryptoScamDB](https://api.cryptoscamdb.org/v1/scams) | Community reports of cryptocurrency scams, JSON | C | 360 min |

ScamSniffer and URLhaus are graded B (usually reliable). Both are
automated or community feeds with some upstream validation, not a paid
provider's review. CryptoScamDB is graded C (fairly reliable) because
entries are community submissions with lighter review.

## CryptoScamDB terms and rate limits

The collector calls one endpoint:

```text
GET https://api.cryptoscamdb.org/v1/scams
```

The documented body is `{"success": true, "result": [ ...entries ]}`.
`addresses` may be a list of strings or an object whose values are
strings or lists of strings. The collector flattens both. The server and
its route list live in the public repository
[CryptoScamDB/api.cryptoscamdb.org](https://github.com/CryptoScamDB/api.cryptoscamdb.org),
which is published under the MIT License
([LICENSE](https://github.com/CryptoScamDB/api.cryptoscamdb.org/blob/master/LICENSE)).
The companion site repository
[CryptoScamDB/cryptoscamdb.org](https://github.com/CryptoScamDB/cryptoscamdb.org)
is also MIT. Ledgerhound stores entries for defensive intelligence. It
does not claim ownership of upstream submissions. Check those LICENSE
files before you redistribute a bulk copy of the upstream dataset on its
own.

The project does not publish a numeric request quota. Maintainers have
asked clients to cache the full `/v1/scams` document instead of polling
one indicator at a time. This collector issues a single GET per run. The
configured cadence is 360 minutes, which is the rate limit Ledgerhound
applies on its side.

Chainabuse was not used. Its API requires a key, and its terms restrict
how reports may be redistributed. CryptoScamDB's published API and MIT
licence are the clearer fit.

## URLhaus and ScamSniffer

URLhaus recent URLs are the public CSV at
`https://urlhaus.abuse.ch/downloads/csv_recent/`. abuse.ch publishes terms
of use in the comment header of that file. Ledgerhound stores the rows it
parses and does not claim to be abuse.ch.

ScamSniffer publishes `blacklist/domains.json` and `blacklist/address.json`
from [scamsniffer/scam-database](https://github.com/scamsniffer/scam-database).
The collector reads those two JSON arrays. Each string becomes one raw
record.

## Known-address labels

`ledgerhound/enrich/labels/data/known_addresses.yaml` holds mixer, bridge,
and exchange address sets. A non-empty set must carry both `source` and
`source_url`. The loader rejects a populated set that lacks either.

Populated today:

- Tornado Cash mixer contracts on Ethereum (38 addresses). Source: the
  U.S. Treasury OFAC press release of 2022-08-08,
  <https://ofac.treasury.gov/recent-actions/20220808>. Confidence is below
  1 because the sanctions status of those contracts has been litigated.
  The addresses still identify the mixer pools. This set is independent of
  the live OFAC SDN refresh.

Empty on purpose:

- Bridges. No freely checkable bulk list was bundled.
- Exchange deposit addresses. Those usually come from proprietary
  clustering, and a guessed deposit address would make tracing stop at
  the wrong place.
- Exchange hot wallets. A hot-wallet row is added only when a public
  document names that address: an exchange proof-of-reserves address list
  or the exchange's own disclosure, with the page in `source_url`. This
  repository does not scrape those pages and does not query a chain to
  find candidates. No address met that bar, so the hot-wallet set ships
  empty. The schema and the loader check are in place.

OFAC SDN matches are a separate label (`enrich/labels/ofac.py`), refreshed
on a TTL and cached locally. They are not part of the hot-wallet set.
