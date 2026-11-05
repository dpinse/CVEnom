"""Shared seen-set tracking for append-only feeds (e.g. KEV catalogs)."""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta


def track_new(
    state: dict,
    current: set[str],
    *,
    added_dates: dict[str, date | None],
    max_age_days: int,
    source: str,
    collector_name: str,
    logger: logging.Logger,
) -> list[dict]:
    """Return ``kev_added`` events for ids not previously seen; update ``state["seen"]``.

    First run (no ``"seen"`` key) baselines silently; an EMPTY first run leaves
    ``"seen"`` absent so the next run still baselines. A corrupt persisted value
    (not a list, or any non-str element) is treated as a first run, with a
    warning. ``seen`` becomes the union of prior and current so a truncated feed
    never shrinks the baseline.

    Recency gate: a new id emits only if its added date (``added_dates``) is
    within ``max_age_days`` of today (UTC). An unknown (None/missing) date still
    emits; ingest's DB kev filter bounds that case. Old new-to-us ids are
    absorbed into ``seen`` silently (e.g. after a truncated first baseline).
    """
    stored = state.get("seen")
    baselined = "seen" in state
    if baselined and not (
        isinstance(stored, list) and all(isinstance(x, str) for x in stored)
    ):
        logger.warning("%s: persisted seen state corrupt; re-baselining", collector_name)
        baselined = False

    if not baselined:
        if current:
            state["seen"] = sorted(current)
        else:
            state.pop("seen", None)  # nothing to baseline against yet
        return []

    prior = set(stored)
    cutoff = datetime.now(UTC).date() - timedelta(days=max_age_days)
    events = []
    for cve_id in sorted(current - prior):
        added = added_dates.get(cve_id)
        if added is None or added >= cutoff:
            events.append({"type": "kev_added", "cve_id": cve_id, "source": source})
    state["seen"] = sorted(prior | current)
    return events
