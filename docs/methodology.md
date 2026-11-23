# Methodology

This note is the behaviour of the pipeline: what is stored, what is
allowed to link two indicators, and what has to be true before a report
is written. It is not a diary of how the code was built.

## Extraction

Regex shape is not enough. Random base58 and hex strings often look like
addresses. Each candidate is checked before it is stored.

- Bitcoin legacy addresses (`1...` and `3...`) must pass base58check.
  Bech32 (`bc1...`) must pass the BIP-173 checksum, including the rule
  that mixed case inside one string is invalid.
- Ethereum addresses are `0x` plus 40 hex characters. Mixed-case values
  must match EIP-55. All-lower or all-upper values have no checksum and
  are stored in EIP-55 form so one address is not split by case.
- TRON addresses are base58check with version byte `0x41`.
- Solana addresses are base58 and must decode to 32 bytes.
- URLs are parsed with `urllib.parse`. Tracking parameters (`utm_*`,
  `gclid`, `fbclid`, and similar) are stripped so the same link with
  different tags collapses to one indicator. Bare IP literals are
  rejected as domains. Defanged spellings (`hxxp`, `[.]`, `(dot)`,
  `[at]`) are refanged before matching.
- Telegram handles are `@name`, 5 to 32 characters. Email addresses are
  masked first so `user@example.com` is not read as a handle.
- A URL also produces a domain indicator for its host. Clustering on
  registrar, nameserver, and certificate data uses the domain.

Indicators are upserted on `(type, value)`. `first_seen` and `last_seen`
only widen. Re-running extraction does not duplicate rows.

Punycode is stored as Unicode, one way only, so a domain is not split
across two rows. Homograph domains are therefore stored in decoded form.

## Enrichment

Chain addresses and domains are enriched from public providers. No API
key is required for that stage. The work is asynchronous because it is
mostly waiting on independent calls.

Each data type has a priority list of providers. The registry skips a
provider after repeated failures and tries it again after a cooldown.
The row records which provider answered. `lh providers` shows health for
the current process only. That health is not saved across invocations.

| Data | Primary | Fallback | Limit |
|---|---|---|---|
| BTC address | mempool.space | blockstream.info | Both speak the Esplora API. |
| ETH address | Blockscout | public JSON-RPC | RPC returns balance and nonce only, so that result is marked partial. |
| TRON address | TronGrid | Tronscan | Native TRX transfers only. Token transfers are out of scope and the result is partial. |
| SOL address | public Solana RPC | a second public Solana RPC | Counterparty attribution beyond a simple transfer is a heuristic and is marked partial. |
| Domain DNS | recursive resolver | Cloudflare DNS-over-HTTPS | DoH covers networks that block port 53. |
| Domain registration | RDAP via IANA bootstrap | RDAP via rdap.org, then port-43 WHOIS | WHOIS is a real fallback for TLDs with no usable RDAP. A 404 or a "not found" answer is stored as unregistered, not as an error. |
| Certificates | crt.sh | none | crt.sh is the free comprehensive CT source used here. |
| HTTP fingerprint | request to the domain | none | A dead host or a non-2xx status is a result, not a failure. |
| Sanctions | OFAC SDN list | none | Cached locally so one run does not download the file once per indicator. |

Registration redaction is stored. `registrant_redacted` is set when the
registrant entity is missing, a remark says the record is redacted, RFC
9537 `redacted` entries are present, or a field is a known placeholder
such as `REDACTED FOR PRIVACY`.

Free-text registration fields and HTTP page titles are screened before
they are kept. Phrases that look like prompt instructions are replaced
with a fixed marker. See the tests in `tests/test_prompt_injection.py`.

`lh trace ADDRESS` walks outbound value breadth-first. Default depth is
2 (ceiling 5) and default breadth is 25, highest-value edges first. A
node that is already labeled as an exchange deposit, mixer, bridge, or
sanctioned address is not expanded. Cycles are recorded and not
re-walked. If a cap is hit, `summary.truncated` is set. The trace is
saved when the root address is a tracked indicator, so clustering can
read it later. The trace itself still queries providers. It does not
read the enrichment cache.

Known-address labels are described in
[data-sources.md](data-sources.md). An unsourced populated set is
rejected by the loader.

## Clustering

`lh cluster run` builds five relations, then keeps connected components
whose score clears a threshold.

| Relation | Default weight | Evidence kept |
|---|---|---|
| `shares_receiving_wallet` | 1.0 | Shared outbound wallet, plus the raw-report ids on each side. |
| `shares_cashout_path` | 0.8 | Shared terminal address, its label, and each side's hop distance. |
| `shares_cert` | 0.6 | Issuer and serial (crt.sh does not give a SHA-256 fingerprint), overlapping names, validity window. |
| `shares_template` | 0.5 | Which hash matched (body, favicon, or both) and the fetch times. |
| `shares_registrar_and_ns` | 0.2 | Shared registrar and nameserver set, plus creation dates. |

Weights and thresholds live in `config/clustering.yaml`.

Rules that keep a weak match from becoming a campaign:

- A registrar and nameserver match alone never creates a campaign. A
  component whose only relation is `shares_registrar_and_ns` scores 0.
- An address labeled exchange or mixer is not a linking node for
  `shares_receiving_wallet`. Two scams paying the same mixer are not, by
  that fact, one campaign. `shares_cashout_path` may name a labeled
  terminal as the place funds stopped. That terminal is not a graph node.
- A certificate with more names than `cert.wildcard_san_threshold`
  (default 20) is weighted at `cert.wildcard_weight` (default 0.1).
- Certificate and template matches require both domains to have been
  enriched within the liveness window (default 90 days).

The component score is the sum of edge weights divided by the number of
nodes, plus `campaign.diversity_bonus` (default 0.2) when more than one
relation type is present. The default threshold is 0.5 and it is
inclusive: one `shares_receiving_wallet` edge between two nodes scores
exactly 0.5. Campaigns also need `campaign.min_size` nodes (default 2).

Campaign codes are `LH-YYYY-NNN`, using the year of the run that created
them. Later runs match components to existing campaigns by mutual best
Jaccard similarity (default threshold 0.5, inclusive). A component
matched by several campaigns is a merge. A campaign matched by several
components is a split. Both write a `campaign_events` row. An analyst
display name is not overwritten.

Status is derived. A campaign is `active` when any member's `last_seen`
falls inside `campaign.active_window_days` (default 30). Otherwise it is
`dormant`.

Candidate lists are sorted before use, so the same database produces the
same edges and the same codes. `lh cluster run --dry-run` reports the
result and writes nothing.

Relations only see indicators that have already been enriched. Clustering
does not invent a wallet-to-domain edge. Two components meet only when
some stored indicator sits in both.

## Assessment

`lh assess draft` asks a model for a structured assessment: key
judgements, targeting, ATT&CK techniques, financials, an overall
assessment, attribution, outlook, and gaps. The model drafts. A person
decides. Nothing is published without `lh assess approve`.

The evidence pack is the only campaign data the model sees. It is built
from member indicators, edges, chain and domain projections, certificates,
labels, and source grades. It has no raw provider bodies and no other
campaign. Each item has a stable `ref`. The pack hashes to a sha256 that
is stored on the assessment.

The model call is one forced tool invocation. `OpenAICompatibleLLM` speaks
the OpenAI chat-completions tool format over HTTP, which covers the usual
compatible servers. `LLM_API_KEY` is required only for `lh assess draft`.
The tool schema is the same pydantic model the validator uses
(`AssessmentDraft`), with extra fields forbidden.

Code checks, not just the prompt:

- Every `supporting_evidence_refs` entry must exist on the pack.
- Every `technique_id` must be in the cached MITRE ATT&CK Enterprise set.
  Revoked and deprecated techniques are excluded. The cache is refreshed
  only when it is missing or when a caller asks. Export fails if a cited
  technique is not in that cache. It does not invent a STIX id.
- `attribution.claim` must be null unless some key judgement has
  confidence `high`.
- Confidence is only `low`, `moderate`, or `high`.
- `financial.total_observed_inflow` must equal the pack's own sum of
  `total_received`.

The user message is screened with the same neutraliser used on WHOIS text
and page titles, so an instruction buried in a handle or a title is not
passed through as a command. A tool payload that sets `status`,
`reviewed_by`, or any key outside the schema is rejected and nothing is
stored. Approval is a separate call.

Each draft or edit is a new immutable version. `lh assess draft` refuses
to redraft when the evidence hash is unchanged, unless `--force` is set.
`lh assess edit` re-validates the edited JSON with the same rules.

Review states:

```text
draft ----+--> approved
          |
in_review +--> rejected
```

Approve is legal from `draft` or `in_review`. Reject is legal from
`draft`, `in_review`, or `approved`. A rejected version is not edited in
place. A new version is drafted. Only one approved version may exist per
campaign. `--force` on approve marks the previous approval rejected.

When a pack is rebuilt, the approved version is marked `stale` if its
hash no longer matches. Export refuses a stale approval.

## Export and reports

`get_publishable_assessment` is the gate for export, report, and publish.
It rebuilds the pack and refuses anything that is not approved or that
has gone stale. Export does not call the model and does not use the
network. If the ATT&CK cache is missing, export fails instead of fetching
it.

STIX 2.1 (`lh export stix`), via the `stix2` library:

- An `identity` for Ledgerhound. The author string is Herman K.
  (finsecguy). The approving analyst is in `contact_information`.
- A `campaign`, one `indicator` per member, an `attack-pattern` per cited
  technique, `indicates` and `uses` relationships, and a `report`.
- Confidence on the 0 to 100 scale uses Ledgerhound's own map: low 25,
  moderate 50, high 75. STIX leaves that scale non-normative.
- Chain addresses use a custom `x-crypto-address` pattern. Telegram
  handles use `x-telegram-handle`. Domains and URLs use native objects.
- TLP 2.0 markings are the OASIS objects. The installed `stix2` release
  predates those constants, so the five marking objects are vendored.
- Object ids are UUIDv5 of stable content. Timestamps use the approval
  time. The same approved assessment produces the same bundle bytes.
  Validators may warn that the ids are not UUIDv4. That warning is
  expected.

MISP (`lh export misp`) writes a static feed: `manifest.json`, one JSON
file per event, and `hashes.csv`. Ledgerhound does not call the MISP REST
API. Bitcoin uses the native `btc` attribute. Other chain addresses and
Telegram handles use `text` plus a comment, because MISP has no type for
them (only `btc` and `xmr` are native cryptocurrency types here). Tags use
real taxonomy values: `tlp:<color>`, the estimative-language confidence
predicate, and `misp-galaxy:mitre-attack-pattern` when a technique is
present.

The IOC feed (`lh export feed`) is a static directory: per-campaign JSON,
combined `iocs.json` and `iocs.csv`, `feed.json`, and `index.html`.
Values are defanged unless `--refanged` is set. Addresses and handles
have nothing to defang.

Reports (`lh report render`) use a fixed section order: header, key
judgements, summary, targeting, tradecraft, infrastructure, financial
analysis, assessment, outlook, indicators, sources, and methodology. The
methodology section is generated from the pack (relations, trace depth,
providers, partial or truncated results). The campaign graph is a PNG
when `dot` is installed. Otherwise the DOT source is embedded and the
render still finishes. PDF uses WeasyPrint, imported only when a PDF is
requested. Markdown does not need it.

`lh publish` runs the exporters for one campaign, or for every
publishable campaign with `--all`, and appends a `publications` row.
The MISP feed and the IOC feed describe every publishable campaign, so
each publish rewrites those directories.

## Limitations

- Coverage is the configured public feeds. False positives in those feeds
  are stored until a later stage has evidence to separate them. Extraction
  does not decide that a reported address is malicious.
- A first collect of ScamSniffer pulls its whole blocklist. The first
  extract of that backlog is slow. Later runs with `--since` are smaller.
- Registration lookups use the indicator string as given. A subdomain
  often gets an RDAP 404, which is stored as unregistered even when the
  parent is registered. DNS, certificates, and HTTP for that indicator
  are unaffected.
- The certificate "fingerprint" used for clustering is issuer plus serial,
  not a hash of the certificate.
- Provider health counters live only in the current process.
- `lh trace` always hits live providers. It does not serve the enrichment
  cache. Saved traces are what `shares_cashout_path` reads.
- SOL counterparty splits and TRON token transfers are partial, and the
  rows say so.
- Exchange hot wallets and deposit addresses are empty until a cited
  public source is added. Tracing will not recognise those hops.
- An assessment only knows what enrichment and clustering have already
  stored. It does not re-query providers.
- The evidence hash proves which pack produced a draft. The pack itself
  is not stored, so an old draft cannot be rebuilt after the rows change.
- Reviewer names are free text (`--reviewer`, or the dashboard field).
  They are an audit trail, not an authentication check.
- The ATT&CK cache does not refresh on a timer. Delete it, or ask for a
  refresh, to pick up a new release.
- STIX and MISP ids are UUIDv5. Some STIX validators warn.
- The static MISP files follow the documented feed layout. This stack
  does not import them into a running MISP server.
- The dashboard has no authentication. Do not expose `lh serve` beyond
  the machine that holds the database.
- The dashboard does not run export. A report appears in the UI after
  `lh report` or `lh publish` has written the files.
- The interactive graph is drawn in the browser for the whole campaign.
  Very large campaigns are not specially virtualized.
- Frontend tests are component tests. There is no browser end-to-end
  suite in CI. The sanitised example's dashboard image is produced by a
  headless browser against the local example database.
