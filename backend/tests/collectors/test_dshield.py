import asyncio
import logging
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from cvenom.collectors import base, dshield
from cvenom.collectors.base import REGISTRY
from cvenom.collectors.dshield import DShieldCollector
from cvenom.geoip import GeoResult
from cvenom.models import GeoEvent
from cvenom.pipeline import ingest

NOW = datetime(2026, 11, 5, 14, 37, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)
    monkeypatch.setattr(dshield, "_now", lambda: NOW)


class StubGeo:
    MAP = {
        "79.124.59.78": "BG",
        "1.2.3.4": "CN",
        "5.6.7.8": "CN",
        "9.9.9.9": None,  # known IP, no country
    }

    def __init__(self):
        self.closed = 0

    def lookup(self, ip):
        cc = self.MAP.get(ip)
        return GeoResult(cc, None) if cc else None

    def close(self):
        self.closed += 1


def _rec(ip, attacks, count):
    return {"ip": ip, "attacks": attacks, "count": count,
            "firstseen": "2025-08-16", "lastseen": "2026-11-05"}


def _fixture():
    return [
        _rec("79.124.59.78", 500, 410604),
        _rec("1.2.3.4", 10, 100),
        _rec("5.6.7.8", 20, 250),
        _rec("10.0.0.1", 5, 5),
        _rec("not-an-ip", 5, 5),
        _rec("9.9.9.9", 5, 5),
        _rec("079.124.059.078", 7, 1000),
        "garbage",
    ]


def _make(monkeypatch, geo, payload):
    calls = []

    async def fake_get(url, **kw):
        calls.append((url, kw))
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(dshield, "http_get_json", fake_get)
    monkeypatch.setattr(DShieldCollector, "geoip_factory", staticmethod(lambda: geo))
    return DShieldCollector(), calls


def test_aggregation(monkeypatch):
    geo = StubGeo()
    c, calls = _make(monkeypatch, geo, _fixture())
    res = asyncio.run(c.run())
    assert c.last_error is None
    by = {e.country_code: e for e in res.geo_events}
    assert set(by) == {"BG", "CN"}
    bg, cn = by["BG"], by["CN"]
    assert bg.magnitude == 410604 + 1000  # zero-padded IP resolves to BG
    assert bg.details == {"sources": 2, "targets": 507}
    assert bg.label == "2 scanning sources"
    assert cn.magnitude == 350
    assert cn.details == {"sources": 2, "targets": 30}
    assert cn.source == "dshield" and cn.kind == "scan"
    assert cn.external_id == "CN:2026-11-05T14"
    assert cn.observed_at == datetime(2026, 11, 5, 14, tzinfo=UTC)
    assert calls[0][0] == "https://isc.sans.edu/api/sources/attacks/100/?json"
    assert calls[0][1]["max_bytes"] == 2_000_000


def test_missing_db_empty_warns_no_http(monkeypatch, caplog):
    c, calls = _make(monkeypatch, None, _fixture())
    with caplog.at_level(logging.WARNING):
        res = asyncio.run(c.run())
    assert res.geo_events == []
    assert c.last_error is None
    assert calls == []
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_geoip_closed_on_success(monkeypatch):
    geo = StubGeo()
    c, _ = _make(monkeypatch, geo, _fixture())
    asyncio.run(c.run())
    assert geo.closed == 1


def test_geoip_closed_on_failure(monkeypatch):
    geo = StubGeo()
    c, _ = _make(monkeypatch, geo, RuntimeError("boom"))
    res = asyncio.run(c.run())
    assert res.geo_events == []
    assert isinstance(c.last_error, RuntimeError)
    assert geo.closed == 1


def test_non_list_response_fails_run(monkeypatch):
    geo = StubGeo()
    c, _ = _make(monkeypatch, geo, {"error": "nope"})
    res = asyncio.run(c.run())
    assert res.geo_events == []
    assert c.last_error is not None
    assert geo.closed == 1


def test_same_hour_ids_identical_and_ingest_updates(monkeypatch, db_session):
    geo = StubGeo()
    c, _ = _make(monkeypatch, geo, _fixture())
    r1 = asyncio.run(c.run())
    ingest(db_session, r1)
    payload = _fixture()
    payload[0]["count"] = 999999
    c2, _ = _make(monkeypatch, StubGeo(), payload)
    r2 = asyncio.run(c2.run())
    assert [e.external_id for e in r1.geo_events] == [e.external_id for e in r2.geo_events]
    ingest(db_session, r2)
    rows = db_session.scalars(select(GeoEvent).where(GeoEvent.source == "dshield")).all()
    assert len(rows) == 2
    bg = next(r for r in rows if r.country_code == "BG")
    assert bg.magnitude == 999999 + 1000


def test_registration():
    assert REGISTRY["dshield"] is DShieldCollector
    assert DShieldCollector.cadence_seconds == 3600
