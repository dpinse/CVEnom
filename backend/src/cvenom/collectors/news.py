"""Security-news RSS/Atom collectors with conditional GET."""

from __future__ import annotations

import calendar
import logging
from datetime import UTC, datetime, timedelta

import feedparser
from pydantic import ValidationError

from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    http_get_conditional,
    register,
)
from cvenom.schemas import NormalizedStory

log = logging.getLogger(__name__)

MAX_FEED_BYTES = 5_000_000
MAX_FUTURE_SKEW = timedelta(hours=1)


class NewsFeedCollector(Collector):
    """Base for RSS/Atom news feeds. Subclasses set name, feed_url, source_name."""

    cadence_seconds = 900
    feed_url: str
    source_name: str

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Validators are committed to self.state only once the body is accepted.
        self._pending_validators: dict[str, str] = {}

    async def fetch(self) -> bytes | None:
        self._pending_validators = {}
        status, body, headers = await http_get_conditional(
            self.feed_url,
            etag=self.state.get("etag"),
            last_modified=self.state.get("last_modified"),
            max_bytes=MAX_FEED_BYTES,
        )
        if status == 304:
            return None
        if headers.get("etag"):
            self._pending_validators["etag"] = headers["etag"]
        if headers.get("last-modified"):
            self._pending_validators["last_modified"] = headers["last-modified"]
        return body

    def normalize(self, raw: bytes | None) -> CollectorResult:
        if not raw:
            return CollectorResult()
        # Entity declarations enable billion-laughs / XXE; no legitimate news feed needs them.
        # Stripping NULs collapses UTF-16/UTF-32 (BOM or BOM-less, either endianness) ASCII-range
        # markup back to ASCII, so the marker is found without decoding. Encodings that do not
        # embed ASCII (e.g. EBCDIC) are not covered by this check.
        if b"<!entity" in raw.replace(b"\x00", b"").lower():
            log.warning("%s: feed contains <!ENTITY declarations; refusing to parse", self.name)
            return CollectorResult()
        parsed = feedparser.parse(raw)  # bytes only: never a URL
        if parsed.get("bozo") and not parsed.get("entries"):
            log.warning(
                "%s: malformed feed with no entries: %s", self.name, parsed.get("bozo_exception")
            )
            return CollectorResult()

        now = datetime.now(UTC)
        stories: list[NormalizedStory] = []
        for entry in parsed.entries:
            try:
                link = entry.get("link")
                title = entry.get("title")
                if not link or not title:
                    log.warning("%s: skipping entry without link/title", self.name)
                    continue
                published = _entry_time(entry, now)
                if published - now > MAX_FUTURE_SKEW:
                    published = now
                stories.append(
                    NormalizedStory(
                        url=link,
                        source=self.source_name,
                        title=title,
                        # feedparser-sanitized HTML, not raw: a CVE id only inside a stripped
                        # attribute or script text is not extracted (accepted; ingest sanitizes again).
                        summary=entry.get("summary", "") or "",
                        published=published,
                    )
                )
            except (
                ValidationError, ValueError, TypeError, OverflowError, OSError, AttributeError, KeyError
            ) as exc:
                log.warning("%s: skipping bad entry: %s", self.name, exc)
        self.state.update(self._pending_validators)
        return CollectorResult(stories=stories)


MIN_YEAR, MAX_YEAR = 1970, 2100


def _entry_time(entry, now: datetime) -> datetime:
    for key in ("published_parsed", "updated_parsed"):
        tm = entry.get(key)
        if tm:
            try:
                dt = datetime.fromtimestamp(calendar.timegm(tm), UTC)
            except (OverflowError, OSError, ValueError):
                return now
            if MIN_YEAR <= dt.year <= MAX_YEAR:
                return dt
            return now
    return now


@register
class KrebsCollector(NewsFeedCollector):
    name = "news_krebs"
    feed_url = "https://krebsonsecurity.com/feed/"
    source_name = "Krebs on Security"


@register
class HackerNewsCollector(NewsFeedCollector):
    name = "news_thn"
    feed_url = "https://feeds.feedburner.com/TheHackersNews"
    source_name = "The Hacker News"


@register
class BleepingComputerCollector(NewsFeedCollector):
    name = "news_bleeping"
    feed_url = "https://www.bleepingcomputer.com/feed/"
    source_name = "BleepingComputer"


@register
class SecurityWeekCollector(NewsFeedCollector):
    name = "news_securityweek"
    feed_url = "https://www.securityweek.com/feed/"
    source_name = "SecurityWeek"
