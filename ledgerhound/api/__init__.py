"""Milestone 6: read-heavy dashboard API over the same database the CLI
uses. This layer must never become a second source of truth. Every
rule that already exists in `assess/` or `cluster/` is imported and
called here, never re-expressed. The only writes are draft edits,
approve/reject actions, and campaign display-name renames; everything
else is a read.

No authentication: this is meant to run locally against your own
database, the same trust boundary the CLI already has. A public
deployment would need auth added in front of this app before exposing
it. Nothing here does that today.
"""

from __future__ import annotations

