"""Milestone 5: export & reports.

Everything here only renders what's already approved in the database —
STIX 2.1 bundles, a MISP feed, a static IOC feed, and Markdown/PDF
reports. Nothing in this package calls the LLM or makes a network
request; `assess/attack.py`'s local-cache-only `load_cached_attack_dataset`
is the one piece of milestone 4 machinery reused here, deliberately never
its network-fetching sibling. `gate.py` enforces the one rule everything
else depends on: only a campaign with an approved, non-stale assessment
can be exported or published.
"""

from __future__ import annotations
