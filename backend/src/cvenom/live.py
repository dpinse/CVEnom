"""Live-update notifications over Redis pub/sub (publisher side; sync for Celery)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from cvenom.collectors.base import CollectorResult

CHANNEL = "cvenom:live"


def what_changed(result: CollectorResult) -> list[str]:
    what: set[str] = set()
    if result.cves:
        what.add("lanes")
    if result.stories:
        what.update(("stories", "lanes"))  # stories drive LOUD
    if result.geo_events:
        what.add("geo")
    return sorted(what)


def publish(redis_client, what: list[str], *, now: datetime | None = None) -> None:
    now = now if now is not None else datetime.now(timezone.utc)
    payload = {"type": "updated", "what": sorted(set(what)), "at": now.astimezone(timezone.utc).isoformat()}
    redis_client.publish(CHANNEL, json.dumps(payload))
