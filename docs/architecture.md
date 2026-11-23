# Architecture

```text
sources.yaml --> Collector.run() --> raw_reports
                                    (deduped by source_id, content_hash)
                                         |
                                         v
                               extract.pipeline.run_extraction()
                                         |
                                         v
                     indicators <--> indicator_observations
                                         |
                                         v
                         enrich.scheduler.run_enrichment()
                      (provider registry, fallback, rate limit)
                                         |
                     +-------------------+-------------------+
                     |                                       |
                     v                                       v
            chain address profiles                    domain profiles
            and counterparties                        certs, DNS, HTTP
                     |
                     v
            labels (OFAC and known-address hits)

            lh trace --> traces, trace_edges, trace_nodes
                                         |
                                         v
                         cluster relations (five detectors)
                                         |
                                         v
                                   edges
                                         |
                                         v
                         connected components, scoring,
                         stable campaign ids
                                         |
                                         v
                     campaigns, campaign_members, campaign_events
                                         |
                                         v
                         evidence pack (hashed)
                                         |
                                         v
                         assessment draft, human review
                                         |
                                         v
              STIX 2.1, MISP feed, IOC feed, Markdown/PDF report
                                         |
                                         v
                              publications (append-only)
```

The dashboard (`lh serve`) reads the same database. Write paths in the
API call the same assessment and clustering functions as the CLI.

## Tables

Every table has a UUID primary key and timezone-aware `created_at` and
`updated_at`.

| Table | Role |
|---|---|
| `sources` | Configured feeds. Mirrors `config/sources.yaml` once synced. |
| `raw_reports` | Raw payloads, keyed by `(source_id, content_hash)`. |
| `indicators` | Canonical indicators, keyed by `(type, value)`. |
| `indicator_observations` | Which raw report an indicator was seen in. |
| `enrichment` | Raw provider payloads, tagged with the provider name. |
| `address_profiles` | Latest chain snapshot for one address indicator. |
| `address_counterparties` | Aggregated counterparties (direction, count, value). |
| `address_labels` | Mixer, bridge, exchange, sanctioned, or scam labels. |
| `domain_profiles` | DNS, registration, and HTTP fingerprint for one domain. |
| `domain_certs` | Certificate names observed for a domain. |
| `traces` | One `lh trace` run. |
| `trace_edges` | Hops recorded during that run. |
| `trace_nodes` | Nodes visited, including why a hop stopped. |
| `edges` | One relation between two indicators, with evidence. |
| `campaigns` | A component that cleared the score threshold. |
| `campaign_members` | Indicators in a campaign. |
| `campaign_events` | Merge and split history. |
| `assessments` | Versioned drafts. At most one approved row per campaign. |
| `publications` | Paths and sha256 hashes of files a publish run wrote. |
| `config_overrides` | Live edits of sources, providers, clustering, and runtime settings. |

Monetary amounts are `Decimal` values in the chain's smallest unit.
SQLite stores them as exact decimal strings so the test suite does not
silently turn them into floats.

## Processes

| Command | What it touches |
|---|---|
| `lh collect` | Network. Writes `raw_reports`. |
| `lh extract` | Local. Writes indicators and observations. |
| `lh enrich` | Network. Writes enrichment projections. |
| `lh trace` | Network. Writes traces when the root address is a tracked indicator. |
| `lh cluster run` | Local. Writes edges and campaigns. |
| `lh assess draft` | Network only for the configured LLM, and for the ATT&CK cache if it is missing. |
| `lh export`, `lh report`, `lh publish` | Local. Read an approved assessment and write files. |
| `lh serve` | Local HTTP API and, when `web/dist/` exists, the built dashboard. |

`make example` does not run the network commands. It replays a fixture
through extract, cluster, a local drafter, and export.
