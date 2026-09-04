"""Milestone 4: LLM-drafted campaign assessments with human review.

The LLM drafts; the analyst decides. `evidence.py` assembles the closed
universe of facts a draft may reason from (`EvidencePack`); `attack.py`
validates any MITRE ATT&CK technique a draft cites; `drafter.py` calls
the model and enforces the hard constraints in code, not just the
prompt; `review.py` is the draft -> review -> approve/reject workflow,
including stable versioning and stale-on-evidence-change detection.
Nothing here ever reaches a report without an explicit `lh assess
approve`.
"""

from __future__ import annotations
