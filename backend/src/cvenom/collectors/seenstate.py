"""Shared seen-set tracking for append-only feeds (e.g. KEV catalogs)."""

from __future__ import annotations

import logging


def track_new(
    state: dict,
    current: set[str],
    *,
    source: str,
    collector_name: str,
    logger: logging.Logger,
) -> list[dict]:
    """Return ``kev_added`` events for ids not previously seen; update ``state["seen"]``.

    First run (no ``"seen"`` key) baselines silently. A corrupt persisted value
    re-baselines with a warning. ``seen`` becomes the union of prior and current
    so a truncated feed never shrinks the baseline.
    """
    stored = state.get("seen")
    prior: set[str] = set()
    if "seen" not in state:
        events: list[dict] = []
    elif not isinstance(stored, list):
        logger.warning("%s: persisted seen state corrupt; re-baselining", collector_name)
        events = []
    else:
        prior = {x for x in stored if isinstance(x, str)}
        events = [
            {"type": "kev_added", "cve_id": cve_id, "source": source}
            for cve_id in sorted(current - prior)
        ]
    state["seen"] = sorted(prior | current)
    return events
