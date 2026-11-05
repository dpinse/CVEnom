"""ransomware.live recent-victims collector (Pro API, key-gated, disabled by default).

Verified (docs only): the free v2 API is retired (api.ransomware.live/v2/... is 404). The
"Ransomware.live API PRO" swagger (api-pro.ransomware.live/swagger.json) defines auth as an
`X-API-KEY` header and `GET /victims/recent`. It does NOT define record field names, so the
mapping below is alias-based and defensive: field names are UNVERIFIED against live data.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

from pydantic import ValidationError

from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    http_get_json,
    register,
)
from cvenom.config import get_settings
from cvenom.schemas import NormalizedGeoEvent, NormalizedStory

log = logging.getLogger(__name__)

URL = "https://api-pro.ransomware.live/victims/recent"
_SKIP = (ValidationError, ValueError, TypeError, AttributeError, KeyError, OverflowError, OSError)
_disabled_logged = False


def _log_disabled(name: str) -> None:
    global _disabled_logged
    level = logging.DEBUG if _disabled_logged else logging.INFO
    _disabled_logged = True
    log.log(level, "%s: no RANSOMWARE_LIVE_API_KEY configured; collector disabled", name)


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _first(rec: dict, *keys: str) -> str:
    for k in keys:
        if v := _text(rec.get(k)):
            return v
    return ""


def _parse_time(value: object) -> datetime | None:
    s = _text(value)
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _external_id(group: str, victim: str, observed: datetime) -> str:
    key = "|".join(p.strip().lower() for p in (group, victim, observed.date().isoformat()))
    return hashlib.sha256(key.encode()).hexdigest()


@register
class RansomwareLiveCollector(Collector):
    name = "ransomware_live"
    cadence_seconds = 900

    async def run(self) -> CollectorResult:
        if not get_settings().ransomware_live_api_key:
            _log_disabled(self.name)
            return CollectorResult()
        return await super().run()

    async def fetch(self) -> list | dict:
        key = get_settings().ransomware_live_api_key.get_secret_value()
        return await http_get_json(URL, headers={"X-API-KEY": key})

    def normalize(self, raw) -> CollectorResult:
        if isinstance(raw, dict):
            for k in ("victims", "data", "results"):
                if isinstance(raw.get(k), list):
                    raw = raw[k]
                    break
        if not isinstance(raw, list):
            raise ValueError(f"{self.name}: unexpected response shape {type(raw).__name__}")
        events: list[NormalizedGeoEvent] = []
        stories: list[NormalizedStory] = []
        for rec in raw:
            try:
                event, story = self._one(rec)
            except _SKIP as exc:
                log.warning("%s: skipping bad record: %s", self.name, exc)
                continue
            events.append(event)
            if story:
                stories.append(story)
        return CollectorResult(geo_events=events, stories=stories)

    def _one(self, rec) -> tuple[NormalizedGeoEvent, NormalizedStory | None]:
        group = _first(rec, "group", "group_name")
        victim = _first(rec, "victim", "post_title")
        if not group or not victim:
            raise ValueError("missing group/victim")
        observed = None
        for k in ("discovered", "published", "attackdate"):
            observed = _parse_time(rec.get(k))
            if observed:
                break
        if observed is None:
            raise ValueError("no parseable timestamp")

        def build(url: str | None, country: str | None) -> NormalizedGeoEvent:
            details = {"group": group}
            if activity := _first(rec, "activity", "sector"):
                details["activity"] = activity
            return NormalizedGeoEvent(
                source="ransomware_live",
                external_id=_external_id(group, victim, observed),
                kind="victim",
                country_code=country,
                observed_at=observed,
                label=f"{group}: {victim}",
                story_url=url,
                details=details,
            )

        country = _first(rec, "country") or None
        try:
            return self._with_urls(rec, group, victim, observed, build, country)
        except ValidationError:
            if country is None:
                raise
            return self._with_urls(rec, group, victim, observed, build, None)

    def _with_urls(self, rec, group, victim, observed, build, country):
        story = None
        url = None
        for k in ("url", "post_url", "website"):
            cand = rec.get(k)
            if not _text(cand):
                continue
            try:
                story = NormalizedStory(
                    url=_text(cand),
                    source="ransomware.live",
                    title=f"{victim} listed by {group}",
                    summary=_first(rec, "description"),
                    published=observed,
                )
            except ValidationError:
                continue
            url = story.url
            break
        return build(url, country), story
