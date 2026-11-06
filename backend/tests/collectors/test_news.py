import codecs
import logging
import time
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

import feedparser
import httpx
import pytest
from sqlalchemy import select

from cvenom.collectors import base
from cvenom.collectors.base import REGISTRY, CollectorResult
from cvenom.collectors.news import NewsFeedCollector
from cvenom.models import Story, StoryCveLink
from cvenom.pipeline import ingest

FIX = Path(__file__).parent.parent / "fixtures"
URL = "https://example.test/feed"


class _Feed(NewsFeedCollector):
    name = "news_test"
    feed_url = URL
    source_name = "Test Source"


def _fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)


@pytest.fixture
def no_parse(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("feedparser must not be called")

    monkeypatch.setattr(feedparser, "parse", boom)


def test_rss_entries_map_to_stories_and_skip_bad_scheme():
    res = _Feed().normalize(_fx("rss_krebs.xml"))
    assert len(res.stories) == 2
    s = res.stories[0]
    assert s.source == "Test Source"
    assert "CVE-2026-109618" in s.title
    assert s.url.startswith("https://krebsonsecurity.com/")
    assert s.published == datetime(2026, 11, 3, 14, 30, tzinfo=UTC)
    assert s.published.utcoffset() == timedelta(0)
    assert s.summary.startswith("<p>")  # markup kept; ingest sanitizes (feedparser drops script)
    assert res.stories[1].published == datetime(2026, 11, 2, 14, 0, tzinfo=UTC)
    assert all("javascript" not in x.url for x in res.stories)


def test_atom_entries_map_to_stories_utc_with_updated_fallback():
    res = _Feed().normalize(_fx("atom_sample.xml"))
    assert len(res.stories) == 2
    assert res.stories[0].published == datetime(2026, 11, 4, 6, 15, tzinfo=UTC)
    assert res.stories[1].published == datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize("fixture", ["rss_billion_laughs.xml", "rss_xxe.xml"])
def test_entity_declarations_refused_without_parsing(fixture, no_parse, caplog):
    start = time.monotonic()
    with caplog.at_level(logging.WARNING):
        res = _Feed().normalize(_fx(fixture))
    assert time.monotonic() - start < 1
    assert res.stories == []
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_malformed_xml_with_no_entries_is_empty_with_warning(caplog):
    with caplog.at_level(logging.WARNING):
        res = _Feed().normalize(b"<rss><channel><item><title>oops")
    assert res.stories == []
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_body_that_is_a_local_path_is_never_opened(tmp_path):
    # feedparser treats a bytes/str argument as a path/URL candidate and opens it if it exists.
    # A feed body that is merely a filesystem path must be parsed as content, never opened.
    local = tmp_path / "planted.xml"
    local.write_bytes(_fx("rss_krebs.xml"))
    res = _Feed().normalize(str(local).encode())
    assert res.stories == []


def test_missing_link_or_title_skipped():
    xml = (
        b'<rss version="2.0"><channel><title>t</title>'
        b"<item><title>no link</title></item>"
        b"<item><link>https://a.test/x</link></item>"
        b"<item><title>ok</title><link>https://a.test/y</link></item>"
        b"</channel></rss>"
    )
    res = _Feed().normalize(xml)
    assert [s.url for s in res.stories] == ["https://a.test/y"]


def test_future_dated_entry_clamped_to_now():
    future = datetime.now(UTC) + timedelta(days=30)
    xml = (
        '<rss version="2.0"><channel><title>t</title><item><title>f</title>'
        f"<link>https://a.test/f</link><pubDate>{format_datetime(future)}</pubDate>"
        "</item></channel></rss>"
    ).encode()
    before = datetime.now(UTC)
    res = _Feed().normalize(xml)
    after = datetime.now(UTC)
    assert before <= res.stories[0].published <= after


def test_missing_date_defaults_to_now():
    xml = (
        b'<rss version="2.0"><channel><title>t</title><item><title>f</title>'
        b"<link>https://a.test/f</link></item></channel></rss>"
    )
    before = datetime.now(UTC)
    res = _Feed().normalize(xml)
    assert before <= res.stories[0].published <= datetime.now(UTC)


async def test_304_is_successful_empty_and_sends_conditional_headers(respx_mock):
    route = respx_mock.get(URL).mock(return_value=httpx.Response(304))
    c = _Feed(state={"etag": '"abc"', "last_modified": "Tue, 03 Nov 2026 10:00:00 GMT"})
    res = await c.run()
    assert res.stories == []
    assert c.last_error is None
    req = route.calls.last.request
    assert req.headers["If-None-Match"] == '"abc"'
    assert req.headers["If-Modified-Since"] == "Tue, 03 Nov 2026 10:00:00 GMT"
    assert c.state["etag"] == '"abc"'


async def test_200_saves_validators(respx_mock):
    respx_mock.get(URL).mock(
        return_value=httpx.Response(
            200,
            content=_fx("rss_krebs.xml"),
            headers={"ETag": '"new"', "Last-Modified": "Wed, 04 Nov 2026 10:00:00 GMT"},
        )
    )
    c = _Feed()
    res = await c.run()
    assert len(res.stories) == 2
    assert c.state["etag"] == '"new"'
    assert c.state["last_modified"] == "Wed, 04 Nov 2026 10:00:00 GMT"


@pytest.mark.parametrize(
    "body", [_fx("rss_billion_laughs.xml"), _fx("rss_xxe.xml"), b"<rss><channel><title>oops"]
)
async def test_refused_feed_does_not_save_validators(respx_mock, body):
    respx_mock.get(URL).mock(
        return_value=httpx.Response(200, content=body, headers={"ETag": '"bad"'})
    )
    c = _Feed(state={"etag": '"old"'})
    res = await c.run()
    assert res.stories == []
    assert c.state["etag"] == '"old"'
    assert "last_modified" not in c.state


async def test_response_too_large_fails_cleanly(respx_mock):
    respx_mock.get(URL).mock(return_value=httpx.Response(200, content=b"x" * 5_000_001))
    c = _Feed()
    res = await c.run()
    assert res == CollectorResult()
    assert isinstance(c.last_error, base.ResponseTooLarge)


def test_four_subclasses_registered_base_not():
    expected = {
        "news_krebs": ("https://krebsonsecurity.com/feed/", "Krebs on Security"),
        "news_thn": ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News"),
        "news_bleeping": ("https://www.bleepingcomputer.com/feed/", "BleepingComputer"),
        "news_securityweek": ("https://www.securityweek.com/feed/", "SecurityWeek"),
    }
    for name, (url, src) in expected.items():
        cls = REGISTRY[name]
        assert issubclass(cls, NewsFeedCollector)
        assert (cls.feed_url, cls.source_name, cls.cadence_seconds) == (url, src, 900)
    assert NewsFeedCollector not in REGISTRY.values()


def test_end_to_end_ingest_links_cve_and_sanitizes(db_session):
    res = _Feed().normalize(_fx("rss_krebs.xml"))
    ingest(db_session, res)
    story = db_session.scalars(select(Story).where(Story.url.like("%cve-2026-109618%"))).one()
    assert "<" not in story.summary
    assert db_session.get(StoryCveLink, (story.id, "CVE-2026-109618")) is not None


_BOMB = (
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
    '<rss version="2.0"><channel><title>x</title><item><title>&b;</title>'
    "<link>https://a.test/z</link></item></channel></rss>"
)


@pytest.mark.parametrize(
    "body",
    [
        codecs.BOM_UTF16_LE + _BOMB.encode("utf-16-le"),
        codecs.BOM_UTF16_BE + _BOMB.encode("utf-16-be"),
        _BOMB.encode("utf-16-le"),
        codecs.BOM_UTF32_LE + _BOMB.encode("utf-32-le"),
    ],
    ids=["utf16le-bom", "utf16be-bom", "utf16le-nobom", "utf32le-bom"],
)
def test_wide_encoded_entity_bomb_refused_without_parsing(body, no_parse, caplog):
    with caplog.at_level(logging.WARNING):
        res = _Feed().normalize(body)
    assert res.stories == []
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_utf16_feed_without_entities_still_parses():
    xml = (
        '<?xml version="1.0" encoding="utf-16"?><rss version="2.0"><channel><title>x</title>'
        "<item><title>hi</title><link>https://a.test/u</link></item></channel></rss>"
    )
    res = _Feed().normalize(codecs.BOM_UTF16_LE + xml.encode("utf-16-le"))
    assert [s.url for s in res.stories] == ["https://a.test/u"]


def test_malformed_entry_object_is_skipped(monkeypatch):
    good = {"title": "ok", "link": "https://a.test/ok"}

    class Bad(dict):
        def get(self, key, default=None):
            raise AttributeError("boom")

    fake = feedparser.FeedParserDict(bozo=0, entries=[Bad(), good])
    monkeypatch.setattr(feedparser, "parse", lambda raw: fake)
    res = _Feed().normalize(b"<rss/>")
    assert [s.url for s in res.stories] == ["https://a.test/ok"]


def test_out_of_range_dates_fall_back_to_now_and_do_not_fail():
    xml = (
        b'<rss version="2.0"><channel><title>t</title>'
        b"<item><title>a</title><link>https://a.test/a</link>"
        b"<pubDate>Fri, 31 Dec 9999 23:59:59 GMT</pubDate></item>"
        b"<item><title>b</title><link>https://a.test/b</link>"
        b"<pubDate>Mon, 01 Jan 0001 00:00:00 GMT</pubDate></item>"
        b"</channel></rss>"
    )
    before = datetime.now(UTC)
    res = _Feed().normalize(xml)
    after = datetime.now(UTC)
    assert [s.url for s in res.stories] == ["https://a.test/a", "https://a.test/b"]
    assert all(before <= s.published <= after for s in res.stories)
