"""ransomware.live recent-victims collector (Pro API, key-gated, disabled by default).

Verified (docs only): the free v2 API is retired (api.ransomware.live/v2/... is 404). The
"Ransomware.live API PRO" swagger (api-pro.ransomware.live/swagger.json) defines auth as an
`X-API-KEY` header and `GET /victims/recent`. The record field names used below (`id`,
`permalink`, `group`, `victim`, `country`, `activity`, `website`, `attackdate`, `discovered`,
`description`, `press`) were confirmed by the user on 2026-11-05; the older aliases
(`group_name`, `post_title`, `sector`, `published`) are still accepted.

Security (spec E): stories and geo events are keyed on the ransomware.live permalink only.
`post_url` (the leak-site, often `.onion`), `screenshot`, `ransom`, `data_size` and
`infostealer` are never read into any output, and the raw record is never copied wholesale:
story `details` is an explicit allow-list. A record with no usable permalink is skipped.
"""

from __future__ import annotations

import hashlib
import logging
import urllib.parse
from datetime import UTC, datetime

from pydantic import ValidationError

from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    http_get_json,
    register,
)
from cvenom.config import get_settings
from cvenom.schemas import (
    NormalizedGeoEvent,
    NormalizedStory,
    contains_bidi_control,
    contains_onion,
    validate_http_url,
)
from cvenom.textutil import sanitize_text

log = logging.getLogger(__name__)

URL = "https://api-pro.ransomware.live/victims/recent"
PERMALINK_PREFIX = "https://www.ransomware.live/"
MAX_PRESS = 5
MAX_SCAN_LEN = 2048  # website / permalink longer than this are rejected unscanned
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


def _valid_url(value: object) -> str | None:
    try:
        return validate_http_url(value)
    except ValueError:
        return None


def permalink_for(rec: dict) -> str | None:
    """The record's ransomware.live permalink, or None (the record is then skipped).

    Never derived from `post_url`/`url`/`website`: only `permalink` on the ransomware.live
    host, else one built from the record `id`.
    """
    perma = rec.get("permalink")
    if (
        isinstance(perma, str)
        and len(perma) <= MAX_SCAN_LEN
        and perma.startswith(PERMALINK_PREFIX)
        and not contains_onion(perma)
    ):
        if url := _valid_url(perma):
            return url
    rid = rec.get("id")
    if isinstance(rid, bool) or not isinstance(rid, (str, int)):
        return None
    if isinstance(rid, str) and not rid.strip():
        return None
    return PERMALINK_PREFIX + "id/" + urllib.parse.quote(str(rid), safe="")


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _press(value: object) -> list[str]:
    items = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    out: list[str] = []
    for item in items:
        if len(out) >= MAX_PRESS:
            break
        if isinstance(item, str) and (url := _valid_url(item)):
            out.append(url)
    return out


def _story_details(rec: dict, group: str, victim: str) -> dict:
    """Allow-listed story details. Never post_url/screenshot/ransom/data_size/infostealer."""
    website = _str_or_none(rec.get("website"))
    # Overlong values are rejected before any scan. The scan runs on the value as ingest stores
    # it (sanitize_text strips markup), so markup cannot split ".onion" past the check. Bidi
    # controls are rejected outright: reordering can make other text display as ".onion".
    if website is not None and (
        len(website) > MAX_SCAN_LEN
        or contains_onion(clean := sanitize_text(website))
        or contains_bidi_control(clean)
    ):
        website = None  # text only, but a leak-site address must never reach any output
    return {
        "group": group,
        "victim": victim,
        "country": _str_or_none(rec.get("country")),
        "activity": _first(rec, "activity", "sector") or None,
        "website": website,
        "attackdate": _str_or_none(rec.get("attackdate")),
        "discovered": _str_or_none(rec.get("discovered")),
        "press": _press(rec.get("press")),
    }


@register
class RansomwareLiveCollector(Collector):
    name = "ransomware_live"
    # Fair Usage Policy: ransomware.live caches data for 30 minutes and treats polling more
    # often than that as a breach. Poll hourly (never below 1800).
    cadence_seconds = 3600

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

    def _one(self, rec) -> tuple[NormalizedGeoEvent, NormalizedStory]:
        permalink = permalink_for(rec)
        if permalink is None:
            raise ValueError("no ransomware.live permalink or id")
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

        story = NormalizedStory(
            url=permalink,
            source="ransomware.live",
            title=f"{victim} listed by {group}",
            summary=_first(rec, "description"),
            published=observed,
            details=_story_details(rec, group, victim),
        )

        def build(country: str | None) -> NormalizedGeoEvent:
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
                story_url=permalink,
                details=details,
            )

        country = _first(rec, "country") or None
        try:
            return build(country), story
        except ValidationError:
            if country is None:
                raise
            return build(None), story
