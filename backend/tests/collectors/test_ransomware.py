import logging
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from pydantic import SecretStr
from sqlalchemy import select

from cvenom.collectors import base, ransomware
from cvenom.collectors.base import REGISTRY
from cvenom.collectors.ransomware import RansomwareLiveCollector
from cvenom.models import GeoEvent, Story
from cvenom.pipeline import ingest

KEY = "sekrit-key-12345"


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)


@pytest.fixture(autouse=True)
def reset_disabled_flag(monkeypatch):
    monkeypatch.setattr(ransomware, "_disabled_logged", False)


@pytest.fixture
def keyed(monkeypatch):
    s = SimpleNamespace(ransomware_live_api_key=SecretStr(KEY))
    monkeypatch.setattr(ransomware, "get_settings", lambda: s)


def _rec(victim="Acme Corp", group="lockbit5", **kw):
    rec = {
        "id": "abc123",
        "victim": victim,
        "group": group,
        "discovered": "2026-11-04 10:15:30.123456",
        "published": "2026-11-03 08:00:00.000000",
        "country": "US",
        "activity": "Manufacturing",
        "website": "https://acme.example",
        "post_url": "https://ransomware.live/id/abc123",
        "description": "Leak of internal files.",
    }
    rec.update(kw)
    return rec


def _fixture():
    return [
        _rec(),
        _rec("Globex GmbH", "akira", id="def456", country="DE", activity="Finance", website="",
             post_url="https://ransomware.live/id/def456"),
        _rec("Initech", "play", id="ghi789", country="", activity="", website="https://initech.example",
             post_url=None, description=None),
    ]


def _v2(r):
    return {"id": r["id"], "post_title": r["victim"], "group_name": r["group"],
            "discovered": r["discovered"], "post_url": r["post_url"], "country": r["country"],
            "sector": r["activity"], "description": r["description"]}


def _doc(r):
    return {"id": r["id"], "victim": r["victim"], "group": r["group"], "attackdate": r["discovered"],
            "url": r["post_url"], "country": r["country"], "activity": r["activity"],
            "description": r["description"]}


def test_alias_variants_map_identically():
    base = _fixture()
    a = RansomwareLiveCollector().normalize([_v2(r) for r in base])
    b = RansomwareLiveCollector().normalize([_doc(r) for r in base])
    assert [e.model_dump() for e in a.geo_events] == [e.model_dump() for e in b.geo_events]
    # details keep the raw discovered/attackdate as given, so compare everything else
    assert [s.model_dump(exclude={"details"}) for s in a.stories] == [
        s.model_dump(exclude={"details"}) for s in b.stories
    ]
    for sa, sb in zip(a.stories, b.stories, strict=True):
        keys = ("group", "victim", "activity", "country")
        assert [sa.details[k] for k in keys] == [sb.details[k] for k in keys]
    assert len(a.geo_events) == 3
    assert [s.url for s in a.stories] == [
        "https://www.ransomware.live/id/abc123",
        "https://www.ransomware.live/id/def456",
        "https://www.ransomware.live/id/ghi789",
    ]


def test_date_only_attackdate_parses():
    res = RansomwareLiveCollector().normalize(
        [{"id": "d1", "victim": "V", "group": "g", "attackdate": "2026-11-04"}]
    )
    assert res.geo_events[0].observed_at == datetime(2026, 11, 4, tzinfo=UTC)


@pytest.mark.parametrize("wrap", [lambda x: x, lambda x: {"victims": x},
                                  lambda x: {"data": x}, lambda x: {"results": x}])
def test_wrappers(wrap):
    assert len(RansomwareLiveCollector().normalize(wrap(_fixture())).geo_events) == 3


def test_registration():
    assert REGISTRY["ransomware_live"] is RansomwareLiveCollector
    assert RansomwareLiveCollector.cadence_seconds == 3600


def test_normalize_maps_fixture():
    res = RansomwareLiveCollector().normalize(_fixture())
    assert len(res.geo_events) == 3
    e = res.geo_events[0]
    assert (e.source, e.kind, e.country_code) == ("ransomware_live", "victim", "US")
    assert e.label == "lockbit5: Acme Corp"
    assert e.observed_at == datetime(2026, 11, 4, 10, 15, 30, 123456, tzinfo=UTC)
    assert e.details == {"group": "lockbit5", "activity": "Manufacturing"}
    assert e.story_url == "https://www.ransomware.live/id/abc123"
    assert res.geo_events[1].country_code == "DE"
    assert res.geo_events[2].country_code is None
    assert res.geo_events[2].details == {"group": "play"}
    assert len(res.stories) == 3
    s = res.stories[0]
    assert (s.title, s.source, s.summary) == ("Acme Corp listed by lockbit5", "ransomware.live", "Leak of internal files.")
    assert s.published == e.observed_at
    assert res.stories[2].summary == ""
    assert res.stories[2].url == "https://www.ransomware.live/id/ghi789"
    assert res.stories[2].details["website"] == "https://initech.example"
    assert res.cves == []


def test_external_id_stable_and_distinct():
    a1 = RansomwareLiveCollector().normalize([_rec()]).geo_events[0]
    a2 = RansomwareLiveCollector().normalize([_rec(victim="  ACME corp ")]).geo_events[0]
    b = RansomwareLiveCollector().normalize([_rec("Other Co")]).geo_events[0]
    assert a1.external_id == a2.external_id
    assert len(a1.external_id) == 64
    assert a1.external_id != b.external_id


def test_invalid_country_becomes_none_event_kept():
    res = RansomwareLiveCollector().normalize([_rec(country="Atlantis")])
    assert len(res.geo_events) == 1
    assert res.geo_events[0].country_code is None


def test_javascript_permalink_without_id_skips_record():
    rec = _rec(permalink="javascript:alert(1)", website="javascript:alert(2)", post_url="javascript:alert(3)")
    del rec["id"]
    res = RansomwareLiveCollector().normalize([rec])
    assert res.stories == [] and res.geo_events == []


def test_javascript_website_and_post_url_never_become_links():
    res = RansomwareLiveCollector().normalize(
        [_rec(website="javascript:alert(1)", post_url="javascript:alert(2)")]
    )
    assert [s.url for s in res.stories] == ["https://www.ransomware.live/id/abc123"]
    assert res.geo_events[0].story_url == "https://www.ransomware.live/id/abc123"
    assert "alert(2)" not in repr(res)


def test_malformed_record_skipped_others_kept():
    bad = [None, "str", {"group": "x"}, _rec(discovered="garbage", published=None), _rec(victim=None)]
    res = RansomwareLiveCollector().normalize(bad + [_rec("Good Co")])
    assert [e.label for e in res.geo_events] == ["lockbit5: Good Co"]


def test_published_fallback_when_discovered_missing():
    res = RansomwareLiveCollector().normalize([_rec(discovered=None)])
    assert res.geo_events[0].observed_at == datetime(2026, 11, 3, 8, 0, tzinfo=UTC)


def test_empty_list_is_success(keyed, monkeypatch):
    async def fake(url, **kw):
        return []

    monkeypatch.setattr(ransomware, "http_get_json", fake)
    import asyncio

    c = RansomwareLiveCollector()
    res = asyncio.run(c.run())
    assert c.last_error is None and res.geo_events == []


@pytest.mark.parametrize("payload", [{"error": "nope"}, "oops", None, {"data": "x"}])
def test_non_list_response_fails_run(keyed, monkeypatch, payload):
    async def fake(url, **kw):
        return payload

    monkeypatch.setattr(ransomware, "http_get_json", fake)
    import asyncio

    c = RansomwareLiveCollector()
    res = asyncio.run(c.run())
    assert c.last_error is not None
    assert res.geo_events == []


def test_dict_with_list_accepted():
    assert len(RansomwareLiveCollector().normalize({"data": [_rec()]}).geo_events) == 1


def test_no_key_no_http_call(monkeypatch, caplog):
    monkeypatch.setattr(ransomware, "get_settings", lambda: SimpleNamespace(ransomware_live_api_key=None))
    calls = []

    async def fake(url, **kw):
        calls.append(url)
        return []

    monkeypatch.setattr(ransomware, "http_get_json", fake)
    import asyncio

    with caplog.at_level(logging.INFO):
        res = asyncio.run(RansomwareLiveCollector().run())
    assert calls == [] and res.geo_events == []
    assert "disabled" in caplog.text


def test_key_sent_as_header_and_never_logged(keyed, monkeypatch, caplog):
    seen = {}

    async def fake(url, **kw):
        seen.update(kw, url=url)
        return [_rec()]

    monkeypatch.setattr(ransomware, "http_get_json", fake)
    import asyncio

    with caplog.at_level(logging.DEBUG):
        res = asyncio.run(RansomwareLiveCollector().run())
    assert seen["headers"]["X-API-KEY"] == KEY
    assert seen["url"] == "https://api-pro.ransomware.live/victims/recent"
    assert len(res.geo_events) == 1
    assert KEY not in caplog.text


def test_ingest_idempotent(db_session):
    res = RansomwareLiveCollector().normalize(_fixture())
    ingest(db_session, res)
    ingest(db_session, RansomwareLiveCollector().normalize(_fixture()))
    rows = db_session.scalars(select(GeoEvent).where(GeoEvent.source == "ransomware_live")).all()
    assert len(rows) == 3
    assert db_session.query(Story).count() == 3


@pytest.mark.parametrize("bad", ["0001-01-01T00:00:00+05:00", "9999-12-31T00:00:00Z", "1969-01-01"])
def test_out_of_range_dates_skip_only_that_record(bad):
    res = RansomwareLiveCollector().normalize(
        [_rec("Bad Co", discovered=bad, published=None), _rec("Good Co")]
    )
    assert [e.label for e in res.geo_events] == ["lockbit5: Good Co"]
    assert len(res.stories) == 1


def test_discovered_beats_older_attackdate():
    res = RansomwareLiveCollector().normalize([_rec(attackdate="2026-10-01")])
    assert res.geo_events[0].observed_at == datetime(2026, 11, 4, 10, 15, 30, 123456, tzinfo=UTC)


def test_external_id_stable_when_attackdate_added():
    a = RansomwareLiveCollector().normalize([_rec()]).geo_events[0]
    b = RansomwareLiveCollector().normalize([_rec(attackdate="2026-10-01")]).geo_events[0]
    assert a.external_id == b.external_id


def test_attackdate_is_last_resort():
    res = RansomwareLiveCollector().normalize(
        [_rec(discovered=None, published=None, attackdate="2026-10-01")]
    )
    assert res.geo_events[0].observed_at == datetime(2026, 10, 1, tzinfo=UTC)


def test_disabled_message_logged_at_info_once(monkeypatch, caplog):
    import asyncio

    monkeypatch.setattr(ransomware, "get_settings", lambda: SimpleNamespace(ransomware_live_api_key=None))
    with caplog.at_level(logging.DEBUG, logger="cvenom.collectors.ransomware"):
        asyncio.run(RansomwareLiveCollector().run())
        asyncio.run(RansomwareLiveCollector().run())
    disabled = [r for r in caplog.records if "disabled" in r.getMessage()]
    assert [r.levelno for r in disabled] == [logging.INFO, logging.DEBUG]


def test_cadence_respects_fair_use_cache():
    assert RansomwareLiveCollector.cadence_seconds >= 1800


# ------------------------------------------------ spec E: permalinks, never post_url

PERMA = "https://www.ransomware.live/id/abc"


def test_story_url_is_permalink_not_post_url():
    res = RansomwareLiveCollector().normalize(
        [_rec(permalink=PERMA, post_url="http://leak.onion/x", website="https://victim.example")]
    )
    assert [s.url for s in res.stories] == [PERMA]


def test_foreign_permalink_falls_back_to_id():
    res = RansomwareLiveCollector().normalize([_rec(permalink="https://evil.example/id/1", id="xyz")])
    assert [s.url for s in res.stories] == ["https://www.ransomware.live/id/xyz"]
    assert res.geo_events[0].story_url == "https://www.ransomware.live/id/xyz"


def test_id_is_url_quoted():
    res = RansomwareLiveCollector().normalize([_rec(id="a/../b c")])
    assert [s.url for s in res.stories] == ["https://www.ransomware.live/id/a%2F..%2Fb%20c"]


@pytest.mark.parametrize(
    "rec",
    [
        {"permalink": "http://www.ransomware.live/id/x"},  # not https prefix
        {"permalink": "https://www.ransomware.live.evil.example/x"},
        {"permalink": 5},
        {"id": True},
        {"id": False},
        {"id": ""},
        {"id": "   "},
        {"id": None},
        {"id": 1.5},
        {"id": ["x"]},
        {},
    ],
)
def test_permalink_for_rejects(rec):
    assert ransomware.permalink_for(rec) is None


@pytest.mark.parametrize(
    ("rec", "want"),
    [
        ({"permalink": PERMA}, PERMA),
        ({"permalink": PERMA, "id": "other"}, PERMA),
        ({"permalink": "https://www.ransomware.live/id/a b"}, None),  # fails validate_http_url
        ({"permalink": "https://www.ransomware.live/id/a b", "id": "q"}, "https://www.ransomware.live/id/q"),
        ({"id": 42}, "https://www.ransomware.live/id/42"),
        ({"id": "?x=1#y"}, "https://www.ransomware.live/id/%3Fx%3D1%23y"),
    ],
)
def test_permalink_for_accepts(rec, want):
    assert ransomware.permalink_for(rec) == want


def test_record_without_permalink_or_id_is_skipped():
    rec = _rec("No Link Co")
    del rec["id"]
    res = RansomwareLiveCollector().normalize([rec, _rec("Good Co", id="good")])
    assert [e.label for e in res.geo_events] == ["lockbit5: Good Co"]
    assert [s.title for s in res.stories] == ["Good Co listed by lockbit5"]


def test_post_url_and_screenshot_never_stored():
    shot = "https://images.ransomware.live/screenshots/secret-shot.png"
    res = RansomwareLiveCollector().normalize(
        [
            _rec(
                permalink=PERMA,
                post_url="http://leaksiteabcdefghijklmnop.onion/post/acme",
                screenshot=shot,
                ransom="5000000",
                data_size="2TB",
                infostealer={"employees": 12, "url": "http://stealer.onion/"},
            ),
            # no website, no permalink: post_url must never be used as a fallback link
            _rec("Other Co", id="o1", website=None, post_url="http://other.onion/p"),
        ]
    )
    text = repr(res)
    assert ".onion" not in text
    assert shot not in text
    assert "screenshot" not in text and "post_url" not in text
    assert "infostealer" not in text and "ransom'" not in text and "data_size" not in text
    assert "5000000" not in text and "2TB" not in text and "stealer" not in text
    assert all(s.url.startswith(ransomware.PERMALINK_PREFIX) for s in res.stories)
    assert all(e.story_url.startswith(ransomware.PERMALINK_PREFIX) for e in res.geo_events)


def test_details_fields_and_press_filtering():
    res = RansomwareLiveCollector().normalize(
        [
            _rec(
                permalink=PERMA,
                attackdate="2026-11-01",
                press=["https://news.example/a", "javascript:x", "http://p.onion/"],
                extra_field="must not be copied",
            )
        ]
    )
    d = res.stories[0].details
    assert d == {
        "group": "lockbit5",
        "victim": "Acme Corp",
        "country": "US",
        "activity": "Manufacturing",
        "website": "https://acme.example",
        "attackdate": "2026-11-01",
        "discovered": "2026-11-04 10:15:30.123456",
        "press": ["https://news.example/a"],
    }
    assert isinstance(d["website"], str)  # plain text; the frontend never links it


@pytest.mark.parametrize(
    ("press", "want"),
    [
        (None, []),
        ("https://news.example/one", ["https://news.example/one"]),
        ("javascript:alert(1)", []),
        ([f"https://news.example/{i}" for i in range(8)], [f"https://news.example/{i}" for i in range(5)]),
        (["https://a.example/", 5, None, {"u": "https://b.example/"}], ["https://a.example/"]),
        (["http://x.onion/", "https://xn--abc.onion./", "https://ok.example/"], ["https://ok.example/"]),
        (42, []),
    ],
)
def test_press_normalisation(press, want):
    res = RansomwareLiveCollector().normalize([_rec(press=press)])
    assert res.stories[0].details["press"] == want


def test_details_non_str_scalars_become_none():
    res = RansomwareLiveCollector().normalize(
        [_rec(country=7, website=["https://x.example"], attackdate=20261101, discovered=None,
              published="2026-11-03 08:00:00")]
    )
    d = res.stories[0].details
    assert d["country"] is None and d["website"] is None
    assert d["attackdate"] is None and d["discovered"] is None


def test_onion_website_text_dropped():
    res = RansomwareLiveCollector().normalize([_rec(website="http://victimsite.ONION/")])
    assert res.stories[0].details["website"] is None
    assert ".onion" not in repr(res).lower()


def test_geo_event_story_url_is_permalink():
    res = RansomwareLiveCollector().normalize(
        [_rec(permalink=PERMA, post_url="http://leak.onion/x", website="https://victim.example")]
    )
    e = res.geo_events[0]
    assert e.story_url == PERMA
    assert e.details == {"group": "lockbit5", "activity": "Manufacturing"}
    assert e.external_id == RansomwareLiveCollector().normalize([_rec()]).geo_events[0].external_id


def test_ingest_stores_permalink_and_details(db_session):
    ingest(db_session, RansomwareLiveCollector().normalize(
        [_rec(permalink=PERMA, post_url="http://leak.onion/x", press="https://news.example/a")]
    ))
    story = db_session.scalars(select(Story).where(Story.source == "ransomware.live")).one()
    assert story.url == PERMA
    assert story.details["press"] == ["https://news.example/a"]
    assert story.details["group"] == "lockbit5"
    ev = db_session.scalars(select(GeoEvent).where(GeoEvent.source == "ransomware_live")).one()
    assert ev.story_url == PERMA
    assert ".onion" not in repr(story.details) and ".onion" not in (story.summary or "")
