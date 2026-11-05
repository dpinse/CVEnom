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


@pytest.fixture
def keyed(monkeypatch):
    s = SimpleNamespace(ransomware_live_api_key=SecretStr(KEY))
    monkeypatch.setattr(ransomware, "get_settings", lambda: s)


def _rec(victim="Acme Corp", group="lockbit5", **kw):
    rec = {
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
        _rec("Globex GmbH", "akira", country="DE", activity="Finance", website="", post_url="https://ransomware.live/id/def456"),
        _rec("Initech", "play", country="", activity="", website="https://initech.example", post_url=None, description=None),
    ]


def _v2(r):
    return {"post_title": r["victim"], "group_name": r["group"], "discovered": r["discovered"],
            "post_url": r["post_url"], "country": r["country"], "sector": r["activity"],
            "description": r["description"]}


def _doc(r):
    return {"victim": r["victim"], "group": r["group"], "attackdate": r["discovered"],
            "url": r["post_url"], "country": r["country"], "activity": r["activity"],
            "description": r["description"]}


def test_alias_variants_map_identically():
    base = _fixture()
    a = RansomwareLiveCollector().normalize([_v2(r) for r in base if r["post_url"]])
    b = RansomwareLiveCollector().normalize([_doc(r) for r in base if r["post_url"]])
    assert [e.model_dump() for e in a.geo_events] == [e.model_dump() for e in b.geo_events]
    assert [s.model_dump() for s in a.stories] == [s.model_dump() for s in b.stories]
    assert len(a.geo_events) == 2


def test_date_only_attackdate_parses():
    res = RansomwareLiveCollector().normalize([{"victim": "V", "group": "g", "attackdate": "2026-11-04"}])
    assert res.geo_events[0].observed_at == datetime(2026, 11, 4, tzinfo=UTC)


@pytest.mark.parametrize("wrap", [lambda x: x, lambda x: {"victims": x},
                                  lambda x: {"data": x}, lambda x: {"results": x}])
def test_wrappers(wrap):
    assert len(RansomwareLiveCollector().normalize(wrap(_fixture())).geo_events) == 3


def test_registration():
    assert REGISTRY["ransomware_live"] is RansomwareLiveCollector
    assert RansomwareLiveCollector.cadence_seconds == 900


def test_normalize_maps_fixture():
    res = RansomwareLiveCollector().normalize(_fixture())
    assert len(res.geo_events) == 3
    e = res.geo_events[0]
    assert (e.source, e.kind, e.country_code) == ("ransomware_live", "victim", "US")
    assert e.label == "lockbit5: Acme Corp"
    assert e.observed_at == datetime(2026, 11, 4, 10, 15, 30, 123456, tzinfo=UTC)
    assert e.details == {"group": "lockbit5", "activity": "Manufacturing"}
    assert e.story_url == "https://ransomware.live/id/abc123"
    assert res.geo_events[1].country_code == "DE"
    assert res.geo_events[2].country_code is None
    assert res.geo_events[2].details == {"group": "play"}
    assert len(res.stories) == 3
    s = res.stories[0]
    assert (s.title, s.source, s.summary) == ("Acme Corp listed by lockbit5", "ransomware.live", "Leak of internal files.")
    assert s.published == e.observed_at
    assert res.stories[2].summary == ""
    assert res.stories[2].url == "https://initech.example"
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


def test_javascript_url_no_story_and_no_story_url():
    res = RansomwareLiveCollector().normalize(
        [_rec(website="javascript:alert(1)", post_url="javascript:alert(2)")]
    )
    assert res.stories == []
    assert res.geo_events[0].story_url is None
    assert len(res.geo_events) == 1


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
