"""ransomware.live recent-victims collector (token-gated; see report)."""

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

URL = "https://api.ransomware.live/v2/recentvictims"
_SKIP = (ValidationError, ValueError, TypeError, AttributeError, KeyError)


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


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
            log.info("%s: no RANSOMWARE_LIVE_API_KEY configured; collector disabled", self.name)
            return CollectorResult()
        return await super().run()

    async def fetch(self) -> list | dict:
        key = get_settings().ransomware_live_api_key.get_secret_value()
        return await http_get_json(URL, headers={"X-API-KEY": key})

    def normalize(self, raw) -> CollectorResult:
        if isinstance(raw, dict):
            for k in ("data", "victims"):
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
        group, victim = _text(rec.get("group")), _text(rec.get("victim"))
        if not group or not victim:
            raise ValueError("missing group/victim")
        observed = _parse_time(rec.get("discovered")) or _parse_time(rec.get("published"))
        if observed is None:
            raise ValueError("no parseable timestamp")

        def build(url: str | None, country: str | None) -> NormalizedGeoEvent:
            details = {"group": group}
            if activity := _text(rec.get("activity")):
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

        country = _text(rec.get("country")) or None
        try:
            return self._with_urls(rec, group, victim, observed, build, country)
        except ValidationError:
            if country is None:
                raise
            return self._with_urls(rec, group, victim, observed, build, None)

    def _with_urls(self, rec, group, victim, observed, build, country):
        story = None
        url = None
        for cand in (rec.get("post_url"), rec.get("website")):
            if not _text(cand):
                continue
            try:
                story = NormalizedStory(
                    url=_text(cand),
                    source="ransomware.live",
                    title=f"{victim} listed by {group}",
                    summary=_text(rec.get("description")),
                    published=observed,
                )
            except ValidationError:
                continue
            url = story.url
            break
        return build(url, country), story
