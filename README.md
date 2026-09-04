# Ledgerhound

Ledgerhound is a crypto-scam campaign intelligence pipeline. It ingests
public scam and phishing reports, extracts and validates indicators of
compromise (cryptocurrency addresses, domains, URLs, Telegram handles),
enriches them, clusters related indicators into campaigns based on shared
infrastructure and fund flows, and produces STIX 2.1 bundles and written
threat intelligence reports for analysts and downstream tooling.

This document describes the product as a whole and is written for
consumers of its output — analysts, other intel teams, and engineers
integrating Ledgerhound's data — not just for contributors to this repo.

**Status:** All six milestones are implemented — collection, extraction,
enrichment, clustering, assessment, export (STIX 2.1 / MISP / IOC feed /
Markdown+PDF reports), and a browser dashboard over the same database.
See [Roadmap](#roadmap-not-yet-implemented) for what's deliberately out
of scope.

## What intelligence Ledgerhound produces

At full build-out, Ledgerhound is designed to answer three questions an
analyst or automated defense typically has about a crypto scam report:

1. **Is this indicator part of a known campaign?** — Given an address,
   domain, or handle, which cluster of related infrastructure does it
   belong to, and what else is in that cluster?
2. **What does this campaign's infrastructure look like?** — Shared
   receiving wallets, cash-out paths, TLS certificates, DNS
   registrar/nameserver pairs, and phishing page templates, expressed as a
   graph of typed relationships between indicators.
3. **What should a defender or investigator do with this?** — A written
   assessment per campaign summarizing scope, confidence, and
   recommended actions, a machine-readable STIX 2.1 bundle, and a MISP
   feed/IOC feed, all for ingestion into existing threat-intel tooling.

Today, Ledgerhound answers all three: **what validated indicators have
been reported, by whom, how often; what does public data say about them
right now** (on-chain balance and counterparties, downstream fund flow,
DNS/WHOIS/certificate/hosting data, and known-bad labels); **which
indicators are actually part of the same campaign**, evidence-backed by
shared wallets, cash-out paths, TLS certificates, DNS infrastructure, or
phishing-page templates; **a structured written assessment** of that
campaign — key judgements, targeting, MITRE ATT&CK tradecraft, financial
analysis, and outlook — drafted by an LLM from that evidence but never
published without a human's explicit sign-off; **and, once approved, a
publishable set of intelligence products** — a STIX 2.1 bundle, a MISP
feed, a static IOC feed, and a Markdown/PDF report with its methodology
and limitations spelled out, not just its conclusions.

## Sources and methodology

Ledgerhound collects from public, community- or vendor-maintained scam and
phishing feeds. Each source is registered in `config/sources.yaml` with an
[Admiralty/NATO reliability grade](https://en.wikipedia.org/wiki/Admiralty_code)
(A–F) reflecting how much independent corroboration and vetting the source
applies before publishing an entry — this grade is a property of the feed
as a collection process, not of any individual indicator's accuracy, and
is intended to travel downstream into confidence scoring at the assessment
stage.

Sources configured today:

| Source | Type | What it publishes | Reliability |
|---|---|---|---|
| [ScamSniffer](https://github.com/scamsniffer/scam-database) | Phishing feed | Community-reported malicious Web3 domains and wallet addresses, JSON blocklists | B — usually reliable; crowdsourced, no per-entry vetting disclosed |
| [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) | Phishing feed | Recently-reported malicious/malware-distribution URLs, CSV | B — usually reliable; automated + community reporter submissions, abuse.ch applies some validation |

Collection is pull-based and scheduled per source via `cadence_minutes`.
Every fetch is stored verbatim as a `raw_report` before any parsing
happens, so extraction logic can be revised and re-run retroactively
without re-fetching, and so the pipeline has an audit trail back to the
literal upstream payload for every indicator it has ever produced.

**Adding a source** means implementing `ledgerhound.collect.base.Collector`
(see `ledgerhound/collect/scamsniffer.py` for a minimal example) and adding
an entry to `config/sources.yaml`. No other code changes are required —
the CLI and dedupe/storage layer are source-agnostic.

## Extraction methodology

Indicator extraction (`ledgerhound/extract/`) deliberately does not trust
regex shape-matching alone: plenty of random base58/hex strings match an
address's *shape* without being a valid address. Every candidate is
cryptographically or structurally validated before being stored:

- **Bitcoin** — legacy (`1...`/`3...`) addresses are validated against
  their base58check checksum; bech32 (`bc1...`) addresses are validated
  against the BIP-173 checksum, including rejecting addresses that mix
  upper/lowercase within a single string (a BIP-173 requirement, and a
  common corruption pattern in copy-pasted reports).
- **Ethereum** — `0x` + 40 hex chars. Mixed-case addresses are validated
  against their EIP-55 checksum and rejected on mismatch; all-lowercase or
  all-uppercase addresses have no checksum to validate and are
  canonicalized to EIP-55 mixed-case form for storage, so the same address
  never ends up split across multiple casing variants in the database.
- **TRON** — base58check with the TRON version byte (`0x41`), `T`-prefixed.
- **Solana** — base58, decoded and checked for a 32-byte public key.
- **Domains/URLs** — parsed with `urllib.parse`, not string splitting;
  tracking query parameters (`utm_*`, `gclid`, `fbclid`, etc.) are stripped
  during canonicalization so the same phishing link with different
  campaign-tracking tags collapses to one indicator; bare IP literals are
  detected and routed to a separate rejected-IPs bucket rather than being
  stored as domains; already-defanged input (`hxxp`, `[.]`, `(dot)`,
  `[at]`) is refanged before matching, so indicators pasted out of a
  report or forum post are still recognized.
- **Telegram handles** — `@name`, 5–32 chars, with email local-parts
  (`user@example.com`) masked out first so they aren't misread as handles.

A URL's host is stored both as the full URL indicator and, separately, as
a domain indicator — infrastructure-level clustering (shared registrar/NS,
shared certificate) operates on domains, and a scam rarely reuses the
exact same URL path across its full domain footprint.

Extraction is idempotent: indicators are upserted by `(type, value)`, and
`first_seen`/`last_seen` only ever widen to cover the full range of
reports an indicator has appeared in, regardless of what order reports are
processed in. Re-running extraction over already-processed reports creates
no duplicate rows.

## Enrichment methodology

Every chain address and domain indicator gets enriched from public,
keyless sources — **no API key is required to run the full pipeline**,
anywhere. Enrichment is async (`ledgerhound/enrich/`) since it's
dominated by waiting on many independent network calls, not compute.

**Multi-source with automatic fallback.** Every kind of data has at least
two independent providers in a priority-ordered chain. The registry
(`enrich/registry.py`) tracks each provider's health (consecutive
failures, a backoff cooldown) and skips an unhealthy provider
automatically, retrying it after the cooldown elapses. Every enrichment
row records which provider actually served it — provenance that carries
through into any report built on this data. `lh providers` shows current
health; `lh enrich --provider NAME` forces a single source for testing.

| Data | Primary | Fallback | Notes |
|---|---|---|---|
| BTC address | mempool.space | blockstream.info | Both are Esplora-API deployments — genuinely interchangeable. |
| ETH address | Blockscout | public JSON-RPC | RPC has no "history for an address" method, so it only ever returns balance + nonce (`partial=True`). Blockscout leads so the fallback isn't permanently dead code — see the docstring in `enrich/chain/eth.py` for why this inverts the milestone brief's literal "RPC primary" ordering. |
| TRON address | TronGrid | Tronscan | Both parse native TRX transfers only — TRC20/TRC10 token transfers move no native value and aren't valued in this milestone. |
| SOL address | Solana RPC (`api.mainnet-beta.solana.com`) | a second public Solana RPC | Solana's own RPC exposes real address history (`getSignaturesForAddress`), unlike Ethereum, so both sides of this pair are equally complete. Counterparty attribution from a transaction's balance deltas is a heuristic for anything beyond a simple two-party transfer (always `partial=True`). |
| Domain DNS | a full recursive resolver (dnspython) | Cloudflare DNS-over-HTTPS | DoH is a real fallback, not a token one: it survives networks that block raw port-53 DNS. |
| Domain registration | RDAP via IANA's bootstrap registry | RDAP via rdap.org, then real port-43 **WHOIS** | Three-tier chain, all writing the same `DomainRegistrationProfile` shape. RDAP is primary — plain HTTPS/JSON, ICANN-mandated for gTLDs — but deployment isn't universal (`.sk`, `.ch`, and others have no RDAP server in IANA's bootstrap registry at all; `.cz` has an entry but an unreliable server), so classic WHOIS is kept as a real fallback, not dropped: per-TLD server resolved via IANA's own WHOIS referral (never hardcoded), a per-TLD parser (`.sk`, verified against the live registry) with a generic best-effort fallback parser for everything else (`partial=True` when fields can't be extracted). An RDAP 404 or a WHOIS "not found" response is a valid `registered=False` result, not an error. |
| Domain certificates | crt.sh | *(none)* | The one facet without a fallback pair: crt.sh is the only free, comprehensive CT-log aggregator; a real second source means paying for one or implementing the raw CT protocol. Domain enrichment as a whole still has redundancy across its four independent facets. |
| Domain HTTP fingerprint | direct request to the domain | *(none — there's only one "what does this site serve")* | A connection failure, TLS error, or non-2xx status is a valid **result** (a dead/parked domain is itself intelligence), never an error. |
| Sanctioned addresses | OFAC SDN list | — | Refreshed on a TTL, cached locally (`.cache/ofac_sdn.xml` by default) so a run doesn't re-pull a ~30MB file per indicator. |

**GDPR/privacy redaction is stored, never hidden.** `domain_profiles.registrant_redacted`
is set whenever the registrant entity is missing entirely, a top-level RDAP
remark declares redaction, the newer RFC 9537 structured `redacted`
extension is present, or a registrant field holds a known placeholder
(`"REDACTED FOR PRIVACY"` and similar). Redaction status is itself a weak
signal worth keeping — a domain publishing full registrant data is at
least a little more unusual than one that doesn't. Which of the three
registration providers actually served a domain is recorded on
`domain_profiles.registration_provider`, same as the serving provider is
recorded for every other kind of enrichment.

**Fund-flow tracing** (`lh trace ADDRESS`) follows an address's *outbound*
value downstream, breadth-first, up to `--depth` hops (default 2, hard
ceiling 5) and `--breadth` counterparties per hop (default 25, highest-
value edges first). Expansion stops at a node before it's ever queried
further if that node is a known exchange deposit address, mixer, bridge,
or OFAC-sanctioned address — labeled and left as a terminal node. Depth 2
is usually enough precisely because of these stop conditions: a scam
wallet typically reaches a recognizable sink within one or two hops.
Cycles (an address already seen in this trace) are recorded as edges but
never re-expanded. Every cap that was actually hit — a breadth
truncation, the depth ceiling, a provider that couldn't be reached — sets
`summary.truncated` (and prints a warning in `--format table`), because a
trace that silently implies more coverage than it has is worse than one
that admits its limits.

**Known-address labels** (`enrich/labels/`) — mixer, bridge, and exchange-
deposit address sets, each carrying its source and retrieval date; an
unsourced label doesn't get used. `labels/known.py`'s bundled dataset
ships **Tornado Cash's mixer pool contracts populated** (38 addresses,
sourced directly from the U.S. Treasury OFAC's original 2022 designation
press release — a citable primary source, kept as a `mixer` label
independent of the live OFAC feed since that designation's legal status
has since been contested and litigated) and **bridges and exchange
deposit addresses shipped empty by design**: no free, verifiable bulk
dataset exists for either category at the time this was built (exchange
deposit addresses in particular come from proprietary chain-analytics
clustering, not a public feed) — see `enrich/labels/data/known_addresses.yaml`
for the exact reasoning and the schema to populate them yourself.

**Values are exact, never float.** Every monetary field — balances,
counterparty totals, trace edge values — is a Python `Decimal` in the
chain's smallest native unit (satoshi/wei/sun/lamport), backed by a
dialect-portable `PreciseNumeric` column type that stores the exact
decimal string on SQLite (plain `NUMERIC` silently degrades to a lossy
float there) and native arbitrary-precision `NUMERIC` on Postgres.

## Clustering methodology

`lh cluster run` (`ledgerhound/cluster/`) links indicators into an entity
graph via five independent, evidence-backed relations, then groups
connected components above a confidence threshold into campaigns.
Every edge carries the evidence for why it exists — an unexplainable
cluster is not intelligence, so nothing in `edges.evidence` is ever
discarded once persisted. The graph itself is built and traversed with
`networkx`; nothing here reimplements connected-components.

| Relation | Weight | Evidence recorded |
|---|---|---|
| `shares_receiving_wallet` | 1.0 | The shared wallet address, plus the raw-report ids behind each side's observation. |
| `shares_cashout_path` | 0.8 | The shared terminal address, its label type (exchange/mixer/bridge/sanctioned), and each side's hop distance to it. |
| `shares_cert` | 0.6 | A cert identifier (issuer + serial — crt.sh doesn't expose a real SHA-256 fingerprint, so this is the closest stable substitute), the overlapping SANs, issuer, and validity window. |
| `shares_template` | 0.5 | Which hash(es) matched (page body, favicon, or both) and both sides' fetch timestamps. |
| `shares_registrar_and_ns` | 0.2 | The shared registrar and nameserver set, plus both domains' creation dates. |

Weights and every threshold below live in `config/clustering.yaml`, not
hardcoded, so they can be retuned without a code change.

**Rules that keep clusters honest, not just connected:**

- **A registrar/nameserver match alone can never create a campaign.**
  Two unrelated domains parked at the same budget registrar with default
  nameservers is weak corroboration, not a link — `shares_registrar_and_ns`
  only ever adds weight to a component another relation has already
  connected. A component whose only relation type is this one always
  scores `0.0` (`cluster/scoring.py`), no matter how many domains share it.
- **Known exchange/mixer addresses never act as linking nodes.** An
  address labeled `exchange` or `mixer` (`enrich/labels/`) is excluded
  from `shares_receiving_wallet` entirely — two scams both paying the same
  Tornado Cash pool isn't evidence they're related. `shares_cashout_path`
  is the one exception: it's *allowed* to reference a labeled terminal,
  but only as evidence of where each side's funds converge, never as a
  node in the graph itself.
- **Wildcard/shared hosting certs are discounted, not excluded.** A cert
  covering more than `cert.wildcard_san_threshold` SANs (default 20) is
  almost always shared hosting infrastructure rather than scam-specific
  provisioning, so it contributes at a flat `cert.wildcard_weight` (default
  0.1) instead of the normal 0.6.
- **Cert and template matches require temporal proximity.** Two domains
  can only be linked by `shares_cert` or `shares_template` if they were
  both observed live (per `enriched_at`) within
  `cert.liveness_window_days` / `template.liveness_window_days` (default
  90 days each) of each other — a certificate or template reused two
  years apart is a coincidence of infrastructure reuse, not necessarily
  the same operator still active.

**Scoring:** a connected component's score is the sum of its edge
weights divided by its node count, plus a `campaign.diversity_bonus`
(default 0.2) if the component is corroborated by more than one relation
type. A component becomes a campaign if its score is **at or above**
`campaign.score_threshold` (default 0.5) — inclusive, deliberately: a
single `shares_receiving_wallet` edge between exactly two nodes (the
single strongest, most common real-world link) scores exactly `1.0/2 =
0.5`, and a strict `>` would exclude the most basic campaign case a
threshold like this exists to catch. Campaigns additionally require
`campaign.min_size` (default 2) nodes.

**Stable identity across runs.** Campaigns are not recomputed from
scratch and re-numbered every run — each new run's connected components
are matched against existing campaigns by **mutual best Jaccard
similarity** over member sets (`cluster/campaigns.py`), at or above
`campaign.merge_split_jaccard_threshold` (default 0.5, also inclusive for
the same boundary reason: two equal-sized campaigns fully merging land
exactly at `0.5` Jaccard against each original). A component matched by
more than one existing campaign is a **merge** (the highest-Jaccard/
lowest-code campaign survives and absorbs the rest); an existing campaign
matched by more than one new component is a **split** (the
highest-Jaccard component continues the original id; the others become
new campaigns). Every merge or split is recorded as a row in
`campaign_events` with the exact before/after member-id sets and the
related campaign code(s) — a full audit trail of how a campaign's
membership evolved, not just its current state. New campaigns are named
sequentially, `LH-YYYY-NNN` (year of first observation); an
analyst-set `display_name` is never overwritten by a later run.

**Status** is derived, not stored as a manual flag: a campaign is
`active` if any member indicator's `last_seen` falls within
`campaign.active_window_days` (default 30) of the run, else `dormant`.

**Determinism.** Every candidate list, component list, and member-id
comparison is sorted by string form before use — same database state
always produces the same edges, the same components, and the same
campaign codes on every run, with no dependency on dict/set iteration
order or wall-clock timing. `lh cluster run --dry-run` runs the full
pipeline and reports what it would do without committing anything.

**Trace persistence (a milestone-2 gap closed here).** `lh trace` wrote
its results to stdout only through milestone 2, despite the `traces`/
`trace_edges` schema already existing — `shares_cashout_path` depends on
trace data being queryable from the database, so persistence needed to
exist first. `lh trace` now also writes `trace_nodes` (new table: every
node visited, its hop distance, and whether/why it was a terminal) and
persists automatically whenever the traced root is itself a tracked
`Indicator`; if it isn't, results still print but a warning notes they
weren't saved. `shares_cashout_path` always uses only the most recent
trace per root indicator, so re-running `lh trace` with different
depth/breadth doesn't leave stale terminals in the graph.

Inspect the graph directly:

```bash
lh cluster run                          # detect all 5 relations, persist edges + campaigns
lh cluster run --relation shares_cert --dry-run
lh cluster campaigns --status active --min-size 3
lh cluster show LH-2026-001
lh cluster explain 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045   # which campaign, and why
lh cluster graph LH-2026-001 --format dot | dot -Tpng -o campaign.png
```

## Assessment methodology

`lh assess draft CAMPAIGN_ID` (`ledgerhound/assess/`) has an LLM draft a
structured analytic assessment of a campaign — key judgements, targeting
profile, MITRE ATT&CK tradecraft, financial analysis, an overall
assessment, an attribution judgement, an outlook, and explicit gaps. **The
LLM drafts; the analyst decides.** Nothing it produces reaches a report
without an explicit `lh assess approve`, and every hard constraint below
is enforced in code — not just requested in the prompt — so a draft that
violates one is rejected before it's ever stored, not flagged for review
after the fact.

**The evidence pack is the model's entire world.** `assess/evidence.py`
assembles everything Ledgerhound knows about a campaign's members —
indicator identities, every edge and its evidence, chain-address and
domain projections, certs, labels, and the reliability grade of every
contributing source — into one `EvidencePack`. The model sees *only*
that JSON: no raw provider payloads, no network access of its own, and
no visibility into any other campaign. Every item in the pack carries a
stable `ref` string (e.g. `member:<indicator-id>`, derived from the
underlying row's own identity, never random), and the pack serializes to
a deterministic sha256 (`EvidencePack.evidence_hash`) — the same
database state always produces the same hash, which is how staleness
detection and the re-draft guard below both work without ever persisting
the pack itself.

**The model call is forced tool-use, not free text, and the backend is
pluggable.** `drafter.py` never talks to a specific vendor's SDK — it
calls whatever `AssessmentLLM` it's given (`assess/llm.py`), a small
structural interface with one method, `.draft(...)`. The one
implementation shipped, `OpenAICompatibleLLM`, speaks the OpenAI
`/chat/completions` + tool-calling wire format over plain `httpx`, which
is what OpenAI itself, Azure OpenAI, Ollama, LM Studio, Groq, Together,
OpenRouter, and vLLM all implement — pointing `LLM_BASE_URL`/`LLM_MODEL`
at a different one of those switches backends with no code change.
`LLM_API_KEY` is required only for `lh assess draft`; every other
command works with no key set. Anything that isn't OpenAI-compatible at
all just needs a small class of its own with the same `.draft(...)`
signature. Either way, the call forces a single `submit_assessment` tool
call whose input schema is generated directly from the same pydantic
model (`AssessmentDraft`) validation runs against — so a structurally
invalid response is already unusual, not the common case malformed-JSON
parsing would otherwise produce.

**Hard constraints enforced in code:**

- **Every `supporting_evidence_refs` entry must resolve to a real
  evidence-pack item.** Checked against `EvidencePack.all_refs()`; an
  invented or stale ref fails the whole draft.
- **Every `technique_id` must be a real, current MITRE ATT&CK Enterprise
  technique.** `assess/attack.py` fetches MITRE's public STIX bundle once
  (revoked and deprecated techniques excluded), caches a distilled
  `{id: name}` map locally (`ATTACK_STIX_CACHE_PATH`, no TTL — ATT&CK
  ships a handful of releases a year, so a months-old cache is the
  intended steady state), and records which ATT&CK version a draft's
  `ttps` were checked against.
- **`attribution.claim` must be null unless at least one `key_judgement`
  has confidence `"high"`.** Unattributed is the normal, expected
  outcome — the check exists so a campaign is never attributed just to
  look complete.
- **Confidence is exactly `low` / `moderate` / `high`.** The schema types
  every confidence field as that enum, so a value like `"likely"` fails
  pydantic validation outright; words like that are fine in prose, never
  in a confidence field.
- **`financial.total_observed_inflow` must match the evidence pack's own
  computed total exactly.** The model copies a number Ledgerhound already
  computed (summing the chain-address projections' `total_received`
  across the campaign's members); it never does independent arithmetic.

**Versioning, not overwriting.** Every draft — from the LLM or from `lh
assess edit` (opens the current draft's JSON in `$EDITOR`; on save, the
edited JSON is re-validated against every constraint above, exactly like
a fresh draft, and stored as a new version with `edited_by_human=true`)
— is a new, immutable row in `assessments`. Nothing is ever overwritten,
so `lh assess diff CAMPAIGN_ID N M` and the full review history always
have something to show. `lh assess draft` refuses to re-draft when the
evidence hash hasn't changed since the last version (pass `--force` to
override) — there's nothing new for the model to say otherwise.

**Review is a small state machine**, per version:

```
   draft ----+--> approved
             |
 in_review --+--> rejected
```

`approve` is legal from `draft`/`in_review`; `reject` is legal from
`draft`/`in_review`/`approved` (an analyst revoking an approval after
finding a problem); neither is legal from `rejected` — fixing a rejected
version means editing or re-drafting to produce a new one, and approving
an already-approved version is also illegal. **Exactly one approved
version can exist per campaign at a time**, enforced twice: a partial
unique index in the database (the ultimate guarantee) and an
application-level check in `assess/review.py` that raises a clear error
instead of an opaque constraint violation — `lh assess approve --force`
explicitly supersedes an existing approval (marking it `rejected` with a
note; never silently discarded).

**Stale, not silently wrong.** Whenever a fresh evidence pack is built
(drafting or editing), the campaign's currently-approved version (if
any) has its `stale` flag refreshed: `true` whenever the campaign's
evidence has changed since that version's `evidence_hash` was computed.
The export layer (below) refuses to publish a stale approved assessment
until it's re-reviewed — re-checking freshness itself at export time
rather than trusting whether anyone remembered to re-run `lh assess
draft` after the evidence changed.

```bash
lh assess draft LH-2026-001                 # build the pack, call the model, validate, store v1
lh assess show LH-2026-001                  # render the latest version, evidence refs expanded inline
lh assess edit LH-2026-001 --version 1      # edit in $EDITOR; re-validated, stored as a new version
lh assess approve LH-2026-001 --notes "Reviewed against source reports; approved."
lh assess reject LH-2026-001 --notes "Attribution too speculative."
lh assess diff LH-2026-001 1 2
```

## Export & reports methodology

Only a campaign with an **approved, non-stale** assessment can be
exported or published — `ledgerhound/export/gate.py`'s
`get_publishable_assessment` is the one gate every export/report/publish
path shares, and it re-derives staleness from a freshly built evidence
pack rather than trusting a possibly-stale `stale` flag. Nothing in
`ledgerhound/export/` calls the LLM or makes a network request; the one
piece of milestone 4 machinery it reuses is `assess/attack.py`'s
local-cache-only `load_cached_attack_dataset`, deliberately never its
network-fetching sibling — if the ATT&CK cache is missing, export fails
with a clear message instead of silently fetching it.

**STIX 2.1** (`lh export stix`, via the `stix2` library). Per campaign: an
`identity` (Ledgerhound, with the approving analyst in
`contact_information`), a `campaign` object (name/description from the
approved summary, first/last seen), an `indicator` per member, an
`attack-pattern` per TTP, `indicates`/`uses` relationships, and a
`report` wrapping the assessment (`report_types: ["campaign"]`,
`published`, and `confidence` on STIX's 0–100 scale — a documented
Ledgerhound mapping of low/moderate/high onto representative points
25/50/75, not a literal OASIS table, since the spec's own confidence
scale is non-normative). STIX has no native cryptocurrency-address or
messaging-handle observable type, so chain addresses and Telegram
handles use a documented custom `x-crypto-address`/`x-telegram-handle`
type referenced by name inside the indicator's pattern (legal per STIX
2.1's `x-`-prefixed custom-type rule); domains and URLs use their real
native SCOs. TLP marking is applied per the real, OASIS-published TLP
2.0 marking-definition objects (`oasis-open/cti-stix-common-objects`) —
vendored verbatim, since the installed `stix2` library predates TLP 2.0
and only ships the older TLP 1.0 constants. **ATT&CK ids are never
invented**: every `attack-pattern` uses MITRE's own STIX id from the
cached dataset (`assess/attack.py`'s `stix_ids` map, captured from the
same STIX bundle `lh assess draft` already downloads); a technique
missing from that cache fails the export rather than fabricating an id.
Every object's `id` is a UUIDv5 of stable content (campaign code,
indicator type+value, technique id, ...) and every timestamp is pinned
to the assessment's approval time — **the same approved assessment
always produces byte-identical bundle output**, verified directly
against `stix2-validator` in tests (which flags the deliberately-non-v4
ids as a "SHOULD" warning, never an error).

**MISP feed** (`lh export misp`, all publishable campaigns): the static
feed format (`manifest.json` + one JSON file per event + `hashes.csv`)
any MISP instance can add as a feed URL — not the live MISP REST API,
which Ledgerhound never talks to. Attribute types are MISP's real,
current ones (checked against `MISP/PyMISP`'s `describeTypes.json`
during development): `btc` is native; Ethereum/TRON/Solana addresses and
Telegram handles have no native MISP cryptocurrency type (only `btc` and
`xmr` exist as of writing), so they use MISP's generic `text` type with
a comment rather than an invented `eth`/`tron`/`sol` type a real MISP
instance would silently reject. Tags are likewise real, verified
taxonomy values: `tlp:<color>`,
`estimative-language:confidence-in-analytic-judgment="low|moderate|high"`
(confirmed this predicate's values are exactly Ledgerhound's vocabulary,
not assumed), and `misp-galaxy:mitre-attack-pattern="<name> - <TID>"`.

**Static IOC feed** (`lh export feed`, all publishable campaigns): a
GitHub-Pages-ready directory — per-campaign JSON, combined
`iocs.json`/`iocs.csv`, a `feed.json` index, and an `index.html` listing
with status and last-seen per campaign. Defanged by default, straight
from each indicator's own `defanged_value` column (the same one
extraction computed in milestone 1); `--refanged` swaps in the raw
`value` instead — a no-op for chain addresses/handles, which have
nothing to defang either way.

**Reports** (`lh report render`, Markdown then optionally PDF via
`weasyprint`, imported lazily so a Markdown-only render never needs it
importable): twelve fixed sections — Header, Key Judgements, Summary,
Targeting, Tradecraft, Infrastructure, Financial Analysis, Assessment,
Outlook, Indicators of Compromise, Sources & Reliability, and
**Methodology & Limitations**, which is never optional and is entirely
auto-generated from the evidence pack (which relations linked the
campaign, trace depth used, which providers served the data, and every
partial or truncated result — a truncated trace shows up explicitly in
both Financial Analysis and here, never silently dropped). The campaign
graph is rendered via the system `dot` binary (Graphviz) when available;
if it isn't, the report embeds the DOT source as text instead of failing
outright. `reports/<CODE>/` holds the Markdown source committed
alongside the PDF.

**Publishing** (`lh publish CAMPAIGN_ID` or `--all`) runs all of the
above for one campaign — or every publishable campaign — and records a
`publications` row with every artifact's path and sha256 hash (STIX
bundle, MISP event, feed entry, Markdown, PDF). The MISP feed and IOC
feed are collection-level artifacts (one manifest describing every
event/campaign in the directory), so every publish regenerates them
across *every* currently-publishable campaign, not just the one(s) being
published, so the manifest never goes stale relative to what's on disk.

```bash
lh export stix LH-2026-001 --out bundle.json
lh export misp                              # all publishable campaigns
lh export feed --refanged                   # raw values instead of defanged
lh report render LH-2026-001 --format both
lh publish LH-2026-001
lh publish --all
```

## Dashboard

`lh serve` runs a browser UI (FastAPI backend in `ledgerhound/api/`,
React/TypeScript frontend in `web/`) over the same database every other
command uses — it presents what the CLI already computes and never
duplicates it: every write endpoint imports and calls the exact
`assess/`/`cluster/` function the corresponding CLI command does
(`assess.drafter.draft_assessment`, `assess.review.edit_assessment` /
`approve_assessment` / `reject_assessment`), so a validation rule can
never drift between `lh assess edit` and the dashboard's edit form —
they're the same code. Three views: a **campaign dashboard** (browse
campaigns, explore the entity graph, read published reports), an
**assessment review tool** that replaces the `$EDITOR`-based `lh assess
edit` workflow with a proper form, and a **Settings page** for the
config in `config_store.py` below.

**Config store** (`ledgerhound/config_store.py`): `sources`, `providers`,
and `clustering` — each mirroring one of `config/*.yaml` — plus
`runtime` (the assessment-drafting LLM's key/base URL/model, the default
TLP marking, and enrichment concurrency/TTL) are editable live from
either `lh config show/set/reset` or the dashboard's Settings page, both
calling the exact same store — a change from one is visible to the other
immediately, no restart. A domain's row in the `config_overrides` table
takes precedence over its file/env default the moment it's written;
`lh config reset DOMAIN` (or the Settings page's "Reset to default"
button) deletes the row, reverting to that default. `DATABASE_URL` and
logging stay `.env`-only — both are needed before this table can be
reached — and so do filesystem paths and HTTP retry tuning, which are
lower-value things to expose in a settings page than actual behavior
knobs.

**No authentication.** This runs locally against your own database, the
same trust boundary the CLI already has — a public deployment would need
auth added in front of it before exposing it to anyone else.

**Backend** (`ledgerhound/api/`): read-only except draft edits,
approve/reject, and campaign display-name renames. `GET
/api/campaigns/{code}/graph` and the evidence panel both reuse
`assess.evidence.build_evidence_pack` — the exact same evidence pack
`lh assess`/`lh report render` already build — rather than a second
graph-assembly path; `GET .../explain/{indicator_id}` reuses a new
`cluster.graph.explain_indicator` helper factored out of (and now shared
with) `lh cluster explain`. `ledgerhound/stats.py` was split out the
same way so `lh stats` and `GET /api/stats` can't disagree either.

**Frontend** (`web/`, Vite + React + TypeScript strict): TanStack Query
for all data fetching, no ad hoc `useEffect` fetches. Request/response
types are generated from the API's own OpenAPI schema
(`npm run generate:types`, via `openapi-typescript`) into
`web/src/api/schema.ts`, which is committed — a fresh `npm install &&
npm run build` never needs the Python backend importable, only when
types are deliberately regenerated after an API change. The entity graph
(`components/EntityGraph.tsx`) uses `react-force-graph-2d`, force-
directed, nodes colored by indicator type and edges by relation type
with thickness by weight; this is a separate, interactive client-side
view from the static Graphviz-rendered graph embedded in a milestone 5
report — the two intentionally don't share a rendering path. The
assessment review form (`components/DraftEditForm.tsx`) constrains
confidence to a `<select>` over the backend's exact enum, picks evidence
refs from checkboxes built from the real evidence pack rather than free
text, and checks ATT&CK technique ids against `GET
/api/attack/techniques` (the cached dataset, client-side, before submit)
— all of which the server re-validates on save regardless, through the
same `assess/drafter.py` rules the CLI uses. Dark-mode-first styling
(`web/src/styles/theme.css`) throughout, including the graph background,
so nothing mixes a light dashboard shell with a dark graph view.

**Dev vs. prod** are the same one command, `lh serve`, in two shapes:

```bash
# Dev: two processes, hot-reloading frontend
lh serve --reload                 # FastAPI on :8000
cd web && npm run dev             # Vite on :5173, proxies /api/* to :8000

# Prod: one process
cd web && npm run build           # writes web/dist/
lh serve                          # serves the API and web/dist/ together on :8000
```

`web/vite.config.ts`'s dev-server proxy and `ledgerhound/api/main.py`'s
static mount (only activated when `web/dist/` actually exists) were both
verified end-to-end during development, not just read — `lh serve` was
started and curled directly, and separately alongside a real `vite`
dev-server process, to confirm both shapes actually work before calling
this done.

## Known limitations

- **Coverage is only as good as the two configured public feeds.** Neither
  source vets submissions before publication to the degree a paid
  threat-intel provider would; false positives in upstream feeds propagate
  into Ledgerhound's indicator store as-is. Milestone 1 does no
  independent verification of whether a reported address/domain is
  actually malicious — it stores what was reported.
- **First-run backfills over a feed's full history are slow.** ScamSniffer
  publishes its entire historical blocklist on every fetch (there's no
  upstream delta/pagination), so a first `lh collect --all` inserts on the
  order of several hundred thousand raw reports; the first `lh extract`
  over that backlog is I/O-bound on a per-record upsert and can take
  tens of minutes against a cold database. Steady-state incremental runs
  (`lh extract --since <last-run>`) process only the new delta and are
  fast. This is a target for optimization (batched upserts) in a later
  milestone, not a milestone 1 deliverable.
- **Domain canonicalization normalizes punycode to Unicode.** This is a
  deliberate, one-directional choice (never the reverse) so a domain
  can't be split across two indicator rows depending on which form a
  report used — but it means Unicode homograph domains are stored in
  their decoded form, which downstream tooling that expects ASCII/punycode
  must account for.
- **Extraction has no per-language or per-encoding awareness beyond UTF-8
  text matching.** Reports containing indicators as images, PDFs, or in
  languages/scripts that interact unusually with the regexes above are not
  specifically handled.
- **Exchange deposit and bridge address labels ship empty.** No free,
  verifiable bulk dataset exists for either category (real ones come from
  proprietary chain-analytics clustering or paid data) — see "Enrichment
  methodology" above. Fund-flow tracing will not recognize a hop into an
  exchange or bridge unless you populate `enrich/labels/data/known_addresses.yaml`
  yourself; it will still stop at OFAC-sanctioned addresses and the
  (populated) mixer set.
- **SOL and TRON enrichment is coverage-limited by design, not by bug.**
  Solana counterparty attribution is a best-effort heuristic on balance
  deltas for anything beyond a simple transfer; TRON enrichment values
  native TRX transfers only, not TRC20/TRC10 token movements. Both are
  always marked `partial=True` for exactly this reason.
- **Provider health is process-local, not persisted.** `lh providers` run
  on its own always shows every provider healthy — the cooldown/failure
  tracking in `enrich/registry.py` lives only as long as the Python
  process running the command, by design (there's no requirement, or
  clear value, in persisting it across separate CLI invocations).
- **Fund-flow tracing queries live providers, not the enrichment
  cache.** `lh trace` always reflects current on-chain state rather than
  `address_profiles`/`address_counterparties`, and does not benefit from
  (or contribute to) the enrichment TTL/caching `lh enrich` maintains —
  it does now persist its results (`traces`/`trace_edges`/`trace_nodes`,
  as of milestone 3) so `shares_cashout_path` has something to query, but
  every `lh trace` run is still a fresh set of live provider calls, not a
  cache lookup.
- **RDAP/WHOIS lookups target the exact indicator value, not the
  registrable domain.** A `DOMAIN` indicator that's actually a subdomain
  (e.g. `mail.example.com` rather than `example.com`) will typically get
  a 404 from RDAP, since registries answer for registered domains, not
  arbitrary subdomains — observed live during development. Because a 404
  is (correctly, for a real "not registered" case) treated as a valid
  `registered=False` result rather than a failure, a subdomain indicator
  will be recorded as *unregistered* even though its parent domain is
  registered — the chain never falls through to WHOIS for this case,
  since RDAP didn't fail, it just answered a question that wasn't quite
  the right one. DNS, certs, and HTTP fingerprint for the same indicator
  are unaffected either way. Registering the base domain instead (or
  extracting it separately from a subdomain indicator) isn't done in this
  milestone.
- **`shares_cert`'s "fingerprint" is issuer+serial, not a real
  certificate hash.** crt.sh's certificate-transparency data doesn't
  expose a SHA-256 fingerprint directly; `(issuer, serial_number)` is a
  practically-unique substitute for grouping purposes but is not
  cryptographically equivalent to hashing the certificate itself.
- **Clustering only ever links indicators already enriched.** A relation
  can't detect a connection through data that was never fetched — an
  address never run through `lh enrich`, or a domain with no cert/DNS
  data yet, simply produces no candidate edges for that facet. `lh
  cluster run` reflects the current state of the enrichment tables, not
  a live re-check of the underlying infrastructure.
- **No cross-type corroboration within a single relation.** Each
  relation links same-kind evidence (wallet-to-wallet, domain-to-domain);
  a scam that reuses a wallet on one report and a domain certificate on
  another is only linked into one campaign if some other observed
  indicator bridges the two components — clustering never itself infers
  a wallet-to-domain edge directly.
- **Cash-out and wallet relations are still capped by unpopulated bridge
  and exchange-deposit labels** (see "Enrichment methodology" above), so
  `shares_cashout_path` can currently only terminate at a populated mixer
  or OFAC-sanctioned address until
  `enrich/labels/data/known_addresses.yaml` is filled in.
- **An assessment reasons only from what's already in Ledgerhound.** The
  evidence pack reflects the campaign's current enrichment/clustering
  state at draft time; it never re-checks live provider data and knows
  nothing about a member indicator beyond what `lh enrich`/`lh trace`/`lh
  cluster run` have already recorded. A campaign with sparse enrichment
  produces a sparse, gap-heavy assessment — which is the intended
  behavior (see `gaps` in the schema), not a failure.
- **A draft's `evidence_hash` isn't independently re-derivable once the
  underlying database rows change or are deleted.** The hash proves *a*
  specific evidence state produced the draft, and staleness detection
  compares against it correctly, but Ledgerhound doesn't persist the
  full pack — reconstructing exactly what the model saw for a very old
  draft after significant data drift isn't supported.
- **No enforced reviewer identity.** `--reviewer` defaults to the local
  OS username (`getpass.getuser()`) with no authentication behind it;
  `reviewed_by` is an audit-trail field, not an access-control boundary.
- **`lh assess edit` shells out to `$EDITOR` synchronously.** There's no
  non-interactive way to submit an edited draft (e.g. from a script or a
  web UI) yet — that would mean accepting the edited JSON as a file path
  or stdin instead, which isn't built.
- **The MITRE ATT&CK cache has no automatic refresh policy.** Unlike
  OFAC's 24-hour TTL, `attack_stix_cache_path` is refreshed only when
  missing or when a caller explicitly requests it — a new ATT&CK release
  adding techniques won't be picked up until the cache file is deleted
  (or `force_refresh=True` is passed) and `lh assess draft` runs again.
  Export inherits this: it fails outright (never invents an id) if a
  TTP's technique has dropped out of the cached dataset since drafting.
- **The STIX confidence mapping is Ledgerhound's own reasonable choice,
  not a literal external standard.** STIX 2.1's confidence scale is
  explicitly non-normative
  (no single official low/moderate/high → 0–100 table exists); the
  25/50/75 mapping here is documented as ours, not OASIS's, in
  `export/stix.py`.
- **STIX/MISP object ids are UUIDv5, not UUIDv4.** Deliberate, for
  determinism (the same approved assessment must always produce the
  same bundle), but `stix2-validator` and some other STIX tooling treat
  a non-v4 id as a "SHOULD"-level warning, not an error — expect to see
  that warning from any validator, not just Ledgerhound's own tests.
- **Ethereum/TRON/Solana addresses and Telegram handles have no
  first-class STIX or MISP type.** STIX gets a documented custom
  `x-crypto-address`/`x-telegram-handle` pattern type; MISP gets the
  generic `text` attribute type with a comment. `btc`/`domain`/`url`
  are the only indicator kinds with a real native type in either
  format as of writing.
- **The MISP feed's `hashes.csv` and hosting-friendly static IOC feed
  are Ledgerhound's own implementation of documented, publicly-known
  formats, not validated against a real running MISP instance** (no
  MISP server is part of this stack) — tests validate internal
  consistency (manifest ↔ event files ↔ hashes) and real MISP
  type/tag vocabulary, not an actual MISP import.
- **The campaign graph embedded in a report is only a rendered PNG when
  Graphviz's `dot` binary is installed on the machine running `lh report
  render`.** Otherwise the report falls back to embedding the DOT source
  as text — correct and complete, but not a picture — rather than
  failing the whole render.
- **Report PDF rendering depends on `weasyprint` and its system
  Pango/Cairo libraries being installed and importable.** `lh report
  render --format md` never needs them; `--format pdf`/`both` raises a
  clear error (rather than crashing) if they're unavailable, and no
  alternate PDF engine is implemented.
- **`Publication` rows are an append-only audit log, not a lock.**
  Nothing stops republishing the same campaign repeatedly (each creates
  a new row); there's no "latest publication" concept beyond querying
  for the most recent row by `published_at`.
- **No authentication on the dashboard.** It's built to run locally
  against your own database — the same trust boundary the CLI has, not
  a stronger one. Exposing `lh serve` beyond localhost needs auth added
  in front of it first; nothing here does that.
- **The reviewer identity on a dashboard approve/reject is a free-text
  field the caller supplies (or the placeholder `"dashboard"`), not an
  authenticated user.** Same limitation as the CLI's `--reviewer`
  (`getpass.getuser()`, no verification) — `reviewed_by` remains an
  audit-trail field, not an access-control boundary, in either
  interface.
- **The report/STIX/MISP/feed viewers are read-only surfaces over
  whatever's already on disk.** The dashboard never triggers `lh export
  .../lh report render` itself — a campaign only shows up in the Report
  Viewer or Feed Browser after those commands (or `lh publish`) have
  actually run. There's no "export from the browser" button.
- **The interactive entity graph has no built-in size limit or
  virtualization.** `react-force-graph-2d`'s force simulation is
  rendered client-side for however many members/edges a campaign has;
  a very large campaign's graph hasn't been performance-tuned beyond
  what the library does by default.
- **Frontend testing stops at component tests** (Vitest +
  `@testing-library/react`, mocking `react-force-graph-2d` since jsdom
  can't meaningfully run its canvas/d3-force simulation). No end-to-end
  browser tests (e.g. Playwright) exist — calling that out explicitly
  rather than silently shipping without them; adding real E2E coverage
  of the full click-through-the-UI flows is a reasonable next step.

## Roadmap (not yet implemented)

Every planned milestone (collection, extraction, enrichment, clustering,
assessment, export, dashboard) is implemented. Reasonable further work
not in scope for any milestone here: authentication for a non-local
deployment of the dashboard; end-to-end browser tests (Playwright);
direct push integration with a running MISP instance (rather than the
static feed format); multi-analyst review workflows beyond the current
single-approver model.

## Architecture

```
sources.yaml ──► Collector.run() ──► raw_reports (JSONB, deduped by
                                       (source_id, content_hash))
                                              │
                                              ▼
                                    extract.pipeline.run_extraction()
                                              │
                                              ▼
                              indicators ◄──► indicator_observations
                            (validated, canonicalized,           │
                             deduped by (type, value))    (one row per
                                                          indicator × report)
                                              │
                                              ▼
                              enrich.scheduler.run_enrichment()
                          (never-enriched indicators prioritized,
                              then stale refreshes; per-provider
                                  token-bucket rate limited)
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
        enrich.registry.ProviderRegistry                    enrichment (raw, JSONB,
     (fallback chains, per-provider health)                  provider-tagged, verbatim)
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
 chain/{btc,eth,tron,sol}.py   infra/{dns,whois,certs,http}.py
       │                           │
       ▼                           ▼
address_profiles ◄──► address_counterparties     domain_profiles ◄──► domain_certs
       │
       ▼
address_labels (OFAC + known-address hits)

chain.trace.Tracer  ──►  traces ◄──► trace_edges ◄──► trace_nodes
   (via `lh trace`, live            (hop, terminal reason,
    against providers)               labels per visited node)
                                              │
                                              ▼
                              cluster/relations/*.Relation.detect()
                          (wallet, cashout, cert, registrar_ns, template —
                              reads the projection tables above)
                                              │
                                              ▼
                                  edges (synced per relation run)
                                              │
                                              ▼
                                cluster.graph.build_graph()  (networkx)
                                              │
                                              ▼
                          cluster.scoring + cluster.campaigns
                    (connected components ──► score ──► stable-identity
                        match against existing campaigns via Jaccard)
                                              │
                                              ▼
                    campaigns ◄──► campaign_members      campaign_events
                (LH-YYYY-NNN, active/dormant)          (merge/split audit trail)
                                              │
                                              ▼
                              assess.evidence.build_evidence_pack()
                        (members, edges, projections, labels, source
                         grades — the model's entire world, hashed)
                                              │
                                              ▼
                                assess.drafter.draft_assessment()
                     (pluggable-backend tool-use call, forced schema,
                    hard constraints validated in code, not just prompted)
                                              │
                                              ▼
                                        assessments
                     (versioned, draft/in_review/approved/rejected,
                    edit/approve/reject via `lh assess`, never overwritten)
                                              │
                                              ▼
                                export.gate.get_publishable_assessment()
                              (approved AND non-stale, or refuse — the one
                                  rule every export/report/publish path shares)
                    ┌─────────────┬───────────────┬───────────────┬─────────────┐
                    ▼             ▼               ▼               ▼             ▼
              export.stix    export.misp    export.feed    export.report   (lh publish
           (STIX 2.1 bundle) (MISP feed:   (static IOC    (Markdown, then   orchestrates
                              manifest +    site: JSON/    optional PDF     all of these
                              events +      CSV/HTML)      via weasyprint)  for one or
                              hashes.csv)                                   every campaign)
                    └─────────────┴───────────────┴───────────────┴─────────────┘
                                              │
                                              ▼
                                        publications
                        (append-only: which artifacts, their sha256 hashes,
                            and the approved assessment version published)
```

Nineteen tables, all with a UUID primary key and timezone-aware UTC
`created_at`/`updated_at`:

| Table | Purpose |
|---|---|
| `sources` | Configured feeds (mirrors `config/sources.yaml`). |
| `raw_reports` | Deduplicated raw payloads as fetched, JSONB, keyed by `(source_id, content_hash)`. |
| `indicators` | Canonicalized IOCs, keyed by `(type, value)`, with `first_seen`/`last_seen`. |
| `indicator_observations` | Join table: which raw report an indicator was seen in, and when. |
| `enrichment` | Raw provider payloads per indicator, JSONB, provider-tagged — the audit trail behind every projection table below. |
| `address_profiles` | Normalized chain-address snapshot: balance, tx count, first/last on-chain activity, decimals, serving provider. One row per chain indicator, replaced on re-enrichment. |
| `address_counterparties` | Aggregated counterparty relationships for a tracked address (direction, tx count, total value). |
| `address_labels` | Exchange/mixer/bridge/sanctioned/scam labels on a tracked address, with source and confidence. |
| `domain_profiles` | Normalized domain snapshot merging DNS, registration (RDAP or WHOIS), and HTTP-fingerprint facets — including registration/update/expiry dates, status codes, nameservers, redaction status, and which provider served the registration data. |
| `domain_certs` | Certificate-transparency-observed SANs for a tracked domain. |
| `traces` | One `lh trace` run: root address, depth, whether any cap truncated it, summary JSONB. |
| `trace_edges` | Edges discovered during a trace run (src, dst, hop, value, tx count). |
| `trace_nodes` | Every node visited during a trace run: hop distance, whether it was a terminal, why, and its labels at trace time. |
| `edges` | Relationships between indicators inferred by `cluster/relations/`, one row per (src, dst, relation) with its weight and evidence JSONB — full-synced (added/updated/deleted) on every `lh cluster run`. |
| `campaigns` | A connected component that cleared the scoring threshold: code (`LH-YYYY-NNN`), optional analyst `display_name`, status (active/dormant), score, and which relation types corroborate it. |
| `campaign_members` | Join table: which indicators belong to which campaign. |
| `campaign_events` | Audit trail of stable-identity changes across runs: a `merge` or `split`, the related campaign code(s), and the exact before/after member-id sets. |
| `assessments` | One versioned LLM-drafted (or human-edited) campaign assessment: evidence hash, prompt/model used, the draft itself (JSONB), review status, and reviewer/notes. A partial unique index enforces at most one `approved` row per campaign. |
| `publications` | One `lh publish` run: which campaign, which approved assessment version, TLP marking, and a JSONB map of every artifact produced (STIX bundle, MISP event, feed entry, Markdown, PDF) to its path and sha256 hash. Append-only. |

## Getting started

Requires Python 3.12, (for real deployments) Postgres 16, and — only for
the dashboard — Node.js 18+.

```bash
# Install
pip install -e ".[dev]"

# Local Postgres via Docker Compose
cp .env.example .env
docker compose up -d db

# Schema
lh db upgrade

# Collect from all enabled sources, then extract indicators
lh collect --all
lh extract

# Enrich chain addresses and domains from public sources
lh enrich

# Link enriched indicators into campaigns
lh cluster run

# Draft, review, and approve an assessment (needs LLM_API_KEY)
lh assess draft LH-2026-001
lh assess approve LH-2026-001 --notes "Reviewed against source reports; approved."

# Publish everything for that campaign
lh publish LH-2026-001

# See what you've got
lh stats
lh cluster campaigns

# Or browse it all in the dashboard (build once, then one process)
cd web && npm install && npm run build && cd ..
lh serve
```

Run a single source: `lh collect --source scamsniffer`.
Run extraction incrementally: `lh extract --since 2026-09-01T00:00:00Z`.

Enrichment:

```bash
lh enrich --type btc_address --limit 50   # just BTC addresses, capped
lh enrich --force                          # re-enrich even if not stale
lh enrich --provider mempool_space         # force one provider, skip its fallback
lh providers                               # provider health/facets table
lh trace 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --depth 2 --format table
lh trace <address> --format dot | dot -Tpng -o trace.png   # or --format json
```

Config (see "Config store" under Dashboard — the dashboard's Settings
page edits this exact same store):

```bash
lh config show                             # every domain's effective value + override status
lh config show runtime
lh config set runtime tlp_default TLP:AMBER
lh config set runtime enrich_concurrency 10
lh config set clustering --file clustering-override.json   # sources/providers/clustering
lh config reset runtime                    # revert to its file/env default
```

Clustering:

```bash
lh cluster run                             # detect all 5 relations, persist edges + campaigns
lh cluster run --relation shares_cert --relation shares_template
lh cluster run --dry-run                   # report what would change, persist nothing
lh cluster campaigns --status active --min-size 3
lh cluster show LH-2026-001
lh cluster explain <indicator value>       # which campaign it's in, and the evidence path
lh cluster graph LH-2026-001 --format dot  # or --format json
```

No API key is required for any of the above — everything routes through
keyless public providers by design.

Assessment (the one command that needs a key — set `LLM_API_KEY` in
`.env` first; `LLM_BASE_URL`/`LLM_MODEL` default to OpenAI, and can point
at any OpenAI-compatible provider or self-hosted server instead):

```bash
lh assess draft LH-2026-001
lh assess show LH-2026-001
lh assess edit LH-2026-001 --version 1
lh assess approve LH-2026-001 --notes "Reviewed against source reports; approved."
lh assess reject LH-2026-001 --notes "Attribution too speculative."
lh assess diff LH-2026-001 1 2
```

Export & reports (only a campaign with an approved, non-stale assessment
is publishable — no API key or network access needed for any of this):

```bash
lh export stix LH-2026-001 --out bundle.json
lh export misp                              # MISP feed, all publishable campaigns
lh export feed --refanged                   # static IOC site, raw (non-defanged) values
lh report render LH-2026-001 --format both  # Markdown + PDF
lh publish LH-2026-001                      # all of the above for one campaign + a publications row
lh publish --all                            # every publishable campaign
```

Dashboard:

```bash
# Dev (two processes, hot-reloading frontend)
lh serve --reload
cd web && npm run dev

# Prod (one process)
cd web && npm run build && cd ..
lh serve

# Regenerate web/src/api/schema.ts after changing an API pydantic schema
cd web && npm run generate:types
```

### Tests

```bash
pytest
```

The test suite runs entirely against an in-memory SQLite database (no
Docker/Postgres required) via dialect-portable column types
(`ledgerhound/db/types.py`, including a `PreciseNumeric` type that keeps
`Decimal` values exact on SQLite too); it never touches the network —
collector and enrichment-provider tests replay canned responses via
`httpx.MockTransport` (async, via `pytest-asyncio`) built from fixtures in
`tests/fixtures/` and schema-accurate literals verified against the real
APIs during development. The rate limiter is tested against a fake clock,
never a real `sleep`. Assessment tests mock `AssessmentLLM` the same
way — a fake `.draft(...)` returning a canned dict — so the suite never
spends a real API call; `OpenAICompatibleLLM` itself is tested against
`httpx.MockTransport`, checking the request it builds and both response
shapes real backends return, and `assess/attack.py` is tested the same
way via `httpx.MockTransport`, against a small fixture STIX bundle
rather than MITRE's real multi-megabyte one. Export tests
validate real STIX bundles against `stix2-validator` using a vendored
copy of the actual `oasis-open/cti-stix2-json-schemas` schemas
(`tests/fixtures/stix2_schemas/`) — `conftest.py` self-heals a confirmed
packaging defect in the `stix2-validator` PyPI wheel (it ships without
its own bundled schemas) by copying that vendored copy into the
installed package once per environment, so validation works out of the
box after a plain `pip install -e ".[dev]"` with no manual setup. API
tests (`tests/test_api_*.py`) exercise the FastAPI app directly via
`TestClient` with `get_session` overridden to the same in-memory SQLite
session a test seeds — the same `db_session` fixture every other test
uses, with `StaticPool`/`check_same_thread=False` added so it survives
`TestClient` running handlers in a worker thread. Production deployments
always run on Postgres 16, per `docker-compose.yml`.

Frontend tests (component-level only — see "Known limitations" for why
there's no browser/E2E suite):

```bash
cd web
npm run typecheck   # tsc --noEmit, strict mode
npm run test        # vitest
npm run build       # full production build, catches anything typecheck alone wouldn't
```

### Type checking / linting

```bash
mypy --strict ledgerhound
ruff check ledgerhound tests
```
