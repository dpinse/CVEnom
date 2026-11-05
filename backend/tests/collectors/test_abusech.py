import asyncio
import logging
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import SecretStr

from cvenom.collectors import abusech, base
from cvenom.collectors.abusech import FEODO_URL, TF_URL, AbuseChCollector
from cvenom.collectors.base import REGISTRY
from cvenom.config import Settings
from cvenom.geoip import GeoResult

KEY = "s3cr3t-key-VALUE"


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)


class StubGeo:
    MAP = {"1.2.3.4": "CN", "8.8.8.8": "US", "9.9.9.9": "DE", "2001:4860:4860::8888": "US"}

    def __init__(self):
        self.closed = 0
        self.lookups = []

    def lookup(self, ip):
        self.lookups.append(ip)
        cc = self.MAP.get(ip)
        return GeoResult(cc, None) if cc else None

    def close(self):
        self.closed += 1


def _feodo():
    return [
        {"ip_address": "162.243.103.246", "port": 8080, "status": "offline", "hostname": None,
         "as_number": 14061, "as_name": "DIGITALOCEAN-ASN", "country": "US",
         "first_seen": "2022-06-04 21:24:53", "last_online": "2026-11-01", "malware": "Emotet"},
        {"ip_address": "1.2.3.4", "port": 443, "status": "online", "hostname": None,
         "as_number": True, "as_name": "X", "country": "ZZZ",
         "first_seen": "2024-01-02 03:04:05", "last_online": None, "malware": None},
        {"ip_address": "8.8.8.8", "port": 80, "status": "online", "as_number": 15169,
         "first_seen": "garbage", "last_online": "also garbage", "malware": "Qakbot"},
        {"ip_address": "9.9.9.9", "port": 80, "status": "offline",
         "first_seen": "2024-01-02 03:04:05", "last_online": "2026-11-01 10:00:00",
         "malware": "Dridex", "country": None},
        "garbage",
    ]


def _tf(status="ok", data=None):
    if data is None:
        data = [
            {"id": "111", "ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware": "win.x", "malware_printable": "Pretty", "confidence_level": 75,
             "first_seen": "2026-11-03 10:00:00 UTC", "tags": ["a", "b"]},
            {"id": "112", "ioc": "evil.test", "ioc_type": "domain", "malware": "m",
             "first_seen": "2026-11-03 10:00:00"},
            {"id": "113", "ioc": "[2001:4860:4860::8888]:80", "ioc_type": "ip:port", "malware": "m6",
             "confidence_level": float("nan"), "first_seen": "2026-11-03 10:00:00", "tags": None},
            {"id": "114", "ioc": "2001:4860:4860::8888:80", "ioc_type": "ip:port", "malware": "m7",
             "confidence_level": 150, "first_seen": "2026-11-03 10:00:00"},
            {"id": "115", "ioc": "10.0.0.1:80", "ioc_type": "ip:port", "malware": "priv",
             "first_seen": "2026-11-03 10:00:00"},
            {"id": "116", "ioc": "not-an-ip:80", "ioc_type": "ip:port", "malware": "bad",
             "first_seen": "2026-11-03 10:00:00"},
        ]
    return {"query_status": status, "data": data}


def _make(monkeypatch, geo, key=None, feodo=None, tf=None):
    feodo_calls, posts = [], []

    async def fake_get(url, **kw):
        feodo_calls.append((url, kw))
        if isinstance(feodo, Exception):
            raise feodo
        return _feodo() if feodo is None else feodo

    async def fake_post(url, **kw):
        posts.append((url, kw))
        if isinstance(tf, Exception):
            raise tf
        return _tf() if tf is None else tf

    monkeypatch.setattr(abusech, "http_get_json", fake_get)
    monkeypatch.setattr(abusech, "http_post_json", fake_post)
    monkeypatch.setattr(AbuseChCollector, "geoip_factory", staticmethod(lambda: geo))
    monkeypatch.setattr(
        abusech, "get_settings",
        lambda: Settings(abusech_auth_key=SecretStr(key) if key else None),
    )
    return AbuseChCollector(), feodo_calls, posts


def test_registration():
    assert REGISTRY["abusech"] is AbuseChCollector
    assert AbuseChCollector.cadence_seconds == 3600


def test_feodo_mapping_and_geo_fallback(monkeypatch):
    geo = StubGeo()
    c, calls, posts = _make(monkeypatch, geo)
    res = asyncio.run(c.run())
    assert c.last_error is None and posts == []
    assert calls[0][0] == FEODO_URL and calls[0][1]["max_bytes"] == 5_000_000
    by = {e.external_id: e for e in res.geo_events}
    assert set(by) == {"162.243.103.246:8080", "1.2.3.4:443", "9.9.9.9:80"}
    a = by["162.243.103.246:8080"]
    assert (a.source, a.kind, a.country_code, a.asn) == ("feodo", "c2", "US", 14061)
    assert a.label == "Emotet C2" and a.magnitude == 1.0
    assert a.observed_at == datetime(2026, 11, 1, tzinfo=UTC)  # last_online preferred
    assert a.details == {"status": "offline", "port": 8080, "as_name": "DIGITALOCEAN-ASN"}
    b = by["1.2.3.4:443"]
    assert b.country_code == "CN"  # invalid record country -> GeoIP
    assert b.asn is None  # bool ignored
    assert b.label == "Botnet C2" and b.magnitude == 2.0
    assert b.observed_at == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)  # first_seen fallback
    assert by["9.9.9.9:80"].country_code == "DE"  # missing country -> GeoIP
    assert "162.243.103.246" not in geo.lookups  # record country preferred


def test_unparseable_dates_skip_record(monkeypatch):
    c, _, _ = _make(monkeypatch, StubGeo())
    res = asyncio.run(c.run())
    assert "8.8.8.8:80" not in {e.external_id for e in res.geo_events}


def test_geoip_closed_when_fallback_used(monkeypatch):
    geo = StubGeo()
    c, _, _ = _make(monkeypatch, geo)
    asyncio.run(c.run())
    assert geo.lookups and geo.closed == 1


def test_geoip_not_opened_when_no_fallback_needed(monkeypatch):
    opened = []
    c, _, _ = _make(monkeypatch, None, feodo=_feodo()[:1])
    monkeypatch.setattr(
        AbuseChCollector, "geoip_factory", staticmethod(lambda: opened.append(1) or StubGeo())
    )
    res = asyncio.run(c.run())
    assert len(res.geo_events) == 1 and opened == []


def test_geoip_closed_on_failure_after_open(monkeypatch):
    geo = StubGeo()
    c, _, _ = _make(monkeypatch, geo, key=KEY, tf={"query_status": "illegal_query"})
    asyncio.run(c.run())
    assert c.last_error is not None
    assert geo.lookups and geo.closed == 1


def test_no_geoip_available_still_works(monkeypatch):
    c, _, _ = _make(monkeypatch, None)
    res = asyncio.run(c.run())
    assert c.last_error is None
    assert {e.external_id: e.country_code for e in res.geo_events}["1.2.3.4:443"] is None


def test_geoip_factory_error_treated_as_no_db(monkeypatch):
    c, _, _ = _make(monkeypatch, None)

    def boom():
        raise OSError("bad db")

    monkeypatch.setattr(AbuseChCollector, "geoip_factory", staticmethod(boom))
    res = asyncio.run(c.run())
    assert c.last_error is None and len(res.geo_events) == 3


def test_non_list_feodo_fails_run(monkeypatch):
    c, _, _ = _make(monkeypatch, StubGeo(), feodo={"error": "x"})
    res = asyncio.run(c.run())
    assert res.geo_events == [] and c.last_error is not None


def test_threatfox_not_called_without_key(monkeypatch):
    c, _, posts = _make(monkeypatch, StubGeo())
    asyncio.run(c.run())
    assert posts == []


def test_threatfox_with_key(monkeypatch):
    geo = StubGeo()
    c, _, posts = _make(monkeypatch, geo, key=KEY)
    res = asyncio.run(c.run())
    assert c.last_error is None
    assert len(posts) == 1
    url, kw = posts[0]
    assert url == TF_URL
    assert kw["json_body"] == {"query": "get_iocs", "days": 1}
    assert kw["headers"] == {"Auth-Key": KEY}
    tf = {e.external_id: e for e in res.geo_events if e.source == "threatfox"}
    assert set(tf) == {"111", "113", "114"}  # domain, private and invalid ips dropped
    e = tf["111"]
    assert e.kind == "c2" and e.country_code == "CN"
    assert e.label == "Pretty C2"
    assert e.observed_at == datetime(2026, 11, 3, 10, tzinfo=UTC)
    assert e.details == {"threat_type": "botnet_cc", "confidence": 75, "tags": ["a", "b"]}
    assert tf["113"].details["confidence"] is None and tf["113"].details["tags"] == []
    assert tf["114"].details["confidence"] is None  # 150 out of range
    assert tf["114"].label == "m7 C2"


def test_threatfox_splits_on_last_colon(monkeypatch):
    geo = StubGeo()
    data = [{"id": "9", "ioc": "2001:4860:4860::8888:80", "ioc_type": "ip:port", "malware": "m",
             "first_seen": "2026-11-03 10:00:00"}]
    c, _, _ = _make(monkeypatch, geo, key=KEY, tf=_tf(data=data))
    res = asyncio.run(c.run())
    assert [e.external_id for e in res.geo_events if e.source == "threatfox"] == ["9"]
    assert "2001:4860:4860::8888" in geo.lookups


def test_threatfox_no_result_is_empty_not_failure(monkeypatch):
    c, _, _ = _make(monkeypatch, StubGeo(), key=KEY, tf={"query_status": "no_result"})
    res = asyncio.run(c.run())
    assert c.last_error is None
    assert {e.source for e in res.geo_events} == {"feodo"}


def test_threatfox_bad_status_fails_run(monkeypatch):
    c, _, _ = _make(monkeypatch, StubGeo(), key=KEY, tf={"query_status": "unknown_auth_key"})
    res = asyncio.run(c.run())
    assert res.geo_events == [] and c.last_error is not None
    assert KEY not in str(c.last_error)


def test_key_never_logged_on_http_500(monkeypatch, respx_mock, caplog):
    monkeypatch.setattr(AbuseChCollector, "geoip_factory", staticmethod(lambda: None))
    monkeypatch.setattr(
        abusech, "get_settings", lambda: Settings(abusech_auth_key=SecretStr(KEY))
    )
    respx_mock.get(FEODO_URL).mock(return_value=httpx.Response(200, json=[]))
    route = respx_mock.post(TF_URL).mock(return_value=httpx.Response(500))
    c = AbuseChCollector()
    with caplog.at_level(logging.DEBUG):
        res = asyncio.run(c.run())
    assert res.geo_events == [] and c.last_error is not None
    assert route.call_count == 3
    assert route.calls[0].request.headers["Auth-Key"] == KEY
    assert KEY not in caplog.text
    assert KEY not in repr(c.last_error)


def test_external_ids_idempotent(monkeypatch):
    ids = []
    for _ in range(2):
        c, _, _ = _make(monkeypatch, StubGeo(), key=KEY)
        res = asyncio.run(c.run())
        ids.append(sorted((e.source, e.external_id) for e in res.geo_events))
    assert ids[0] == ids[1] and ids[0]


def test_feodo_record_dated_9999_skipped_others_kept(monkeypatch):
    bad = {"ip_address": "5.5.5.5", "port": 80, "status": "online",
           "first_seen": "9999-01-01 00:00:00", "last_online": None, "country": "US"}
    c, _, _ = _make(monkeypatch, StubGeo(), feodo=_feodo() + [bad])
    res = asyncio.run(c.run())
    ids = {e.external_id for e in res.geo_events}
    assert "5.5.5.5:80" not in ids and "1.2.3.4:443" in ids


def test_feodo_non_string_status_and_as_name_become_none(monkeypatch):
    rec = {"ip_address": "5.5.5.5", "port": 80, "status": {"x": 1}, "as_name": ["a"],
           "first_seen": "2026-11-01 00:00:00", "country": "US"}
    c, _, _ = _make(monkeypatch, StubGeo(), feodo=[rec])
    ev = asyncio.run(c.run()).geo_events[0]
    assert ev.details["status"] is None and ev.details["as_name"] is None
    assert ev.magnitude == 1.0


def test_threatfox_non_string_threat_type_becomes_none(monkeypatch):
    data = [{"id": "9", "ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": {"a": 1},
             "malware": "m", "first_seen": "2026-11-03 10:00:00"}]
    c, _, _ = _make(monkeypatch, StubGeo(), key=KEY, feodo=[], tf=_tf(data=data))
    res = asyncio.run(c.run())
    tf = [e for e in res.geo_events if e.source == "threatfox"]
    assert tf[0].details["threat_type"] is None
