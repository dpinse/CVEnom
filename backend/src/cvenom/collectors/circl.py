"""CIRCL OSINT MISP feed: events that name CVEs become stories.

Manifest and per-event responses are size-capped, and attribute URLs inside events are
never read or requested: only the manifest and EVENT_URL for a validated uuid are fetched.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from cvenom.collectors import base
from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    ResponseTooLarge,
    http_get_json,
    register,
)
from cvenom.schemas import NormalizedStory, validate_cve_id

log = logging.getLogger(__name__)

MANIFEST_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
EVENT_URL = "https://www.circl.lu/doc/misp/feed-osint/{uuid}.json"
MAX_MANIFEST_BYTES = 10_000_000
MAX_EVENT_BYTES = 2_000_000
MAX_EVENTS_PER_RUN = 50
MAX_CVES_PER_EVENT = 50
REQUEST_DELAY = 0.2
FIRST_RUN_WINDOW = timedelta(days=7)
SOURCE = "CIRCL OSINT"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _int_ts(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        ts = int(value)  # MISP stores the timestamp as a string or an int
    except (TypeError, ValueError):
        return None
    return ts if ts > 0 else None


def _vuln_ids(event: dict) -> list[str]:
    attrs = [a for a in (event.get("Attribute") or []) if isinstance(a, dict)]
    for obj in event.get("Object") or []:
        if isinstance(obj, dict):
            attrs.extend(a for a in (obj.get("Attribute") or []) if isinstance(a, dict))
    ids: list[str] = []
    for attr in attrs:
        if attr.get("type") != "vulnerability":
            continue
        try:
            cve_id = validate_cve_id(attr.get("value"))
        except ValueError:
            continue
        if cve_id not in ids:
            ids.append(cve_id)
            if len(ids) >= MAX_CVES_PER_EVENT:
                break
    return ids


@register
class CirclOsintCollector(Collector):
    name = "circl_osint"
    cadence_seconds = 3600

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._ts: dict[str, int] = {}  # manifest timestamp of every event attempted this run

    async def fetch(self) -> list[tuple[str, dict]]:
        self._ts = {}
        manifest = await http_get_json(MANIFEST_URL, max_bytes=MAX_MANIFEST_BYTES)
        if not isinstance(manifest, dict):
            raise ValueError("CIRCL manifest is not an object")
        last_ts = _int_ts(self.state.get("last_ts"))
        seen = {u for u in self.state.get("seen_at_last_ts", []) if isinstance(u, str)}
        floor = int((datetime.now(UTC) - FIRST_RUN_WINDOW).timestamp())
        due: list[tuple[int, str]] = []
        for uuid, meta in manifest.items():
            if not isinstance(uuid, str) or not _UUID_RE.fullmatch(uuid):
                continue
            ts = _int_ts(meta.get("timestamp")) if isinstance(meta, dict) else None
            if ts is None:
                continue
            if last_ts is None:
                if ts <= floor:
                    continue
            elif ts < last_ts or (ts == last_ts and uuid in seen):
                continue
            due.append((ts, uuid))
        due.sort()
        out: list[tuple[str, dict]] = []
        for i, (ts, uuid) in enumerate(due[:MAX_EVENTS_PER_RUN]):
            if i:
                await base._sleep(REQUEST_DELAY)
            try:
                event = await http_get_json(EVENT_URL.format(uuid=uuid), max_bytes=MAX_EVENT_BYTES)
            except ResponseTooLarge:
                log.warning("%s: event %s exceeds size cap; skipped", self.name, uuid)
                self._ts[uuid] = ts
                continue
            self._ts[uuid] = ts
            out.append((uuid, event))
        return out

    def normalize(self, raw: list[tuple[str, dict]]) -> CollectorResult:
        stories: list[NormalizedStory] = []
        processed: dict[str, int] = dict(self._ts)
        for uuid, payload in raw or []:
            ev = payload.get("Event") if isinstance(payload, dict) else None
            if not isinstance(ev, dict):
                continue
            ts = self._ts.get(uuid) or _int_ts(ev.get("timestamp"))
            if ts is None:
                continue
            processed[uuid] = ts
            ids = _vuln_ids(ev)
            if not ids:
                continue
            try:
                stories.append(
                    NormalizedStory(
                        url=EVENT_URL.format(uuid=uuid),
                        source=SOURCE,
                        title=str(ev.get("info") or "CIRCL OSINT event"),
                        summary="Vulnerabilities: " + ", ".join(ids),
                        published=datetime.fromtimestamp(_int_ts(ev.get("timestamp")) or ts, UTC),
                    )
                )
            except (ValidationError, ValueError, OverflowError, OSError) as exc:
                log.warning("%s: skipping event %s: %s", self.name, uuid, exc)
        if processed:
            top = max(processed.values())
            at_top = {u for u, t in processed.items() if t == top}
            if _int_ts(self.state.get("last_ts")) == top:
                at_top |= {u for u in self.state.get("seen_at_last_ts", []) if isinstance(u, str)}
            self.state["last_ts"] = top
            self.state["seen_at_last_ts"] = sorted(at_top)
        return CollectorResult(stories=stories)
