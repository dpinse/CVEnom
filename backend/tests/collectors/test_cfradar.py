import asyncio
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from cvenom.collectors import base, cfradar
from cvenom.collectors.base import REGISTRY
from cvenom.collectors.cfradar import CloudflareRadarCollector

TOKEN = "cfp_SECRET_TOKEN_123"
OUT_URL = "https://api.cloudflare.com/client/v4/radar/annotations/outages"
BGP_URL = "https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events"


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)


FIXED_NOW = datetime(2026, 11, 4, 18, 0, tzinfo=UTC)
ENDED = "2026-11-04T12:00:00Z"


@pytest.fixture(autouse=True)
def pinned_now(monkeypatch):
    monkeypatch.setattr(cfradar, "_utcnow", lambda: FIXED_NOW)


@pytest.fixture(autouse=True)
def reset_disabled_flag(monkeypatch):
    monkeypatch.setattr(cfradar, "_disabled_logged", False)


@pytest.fixture
def keyed(monkeypatch):
    s = SimpleNamespace(cf_radar_token=SecretStr(TOKEN))
    monkeypatch.setattr(cfradar, "get_settings", lambda: s)


def _outage(id="out-1", locations=("IR", "IQ"), details=None, **kw):
    rec = {
        "id": id,
        "startDate": "2026-11-04T10:00:00Z",
        "endDate": None,
        "locations": list(locations),
        "asns": [12880, 58224],
        "outage": {"outageCause": "GOVERNMENT_DIRECTED", "outageType": "NATIONWIDE"},
        "scope": "Nationwide",
        "description": "Internet shutdown",
    }
    if details is not None:
        rec["locationsDetails"] = details
    rec.update(kw)
    return rec


def _hijack(id=7, **kw):
    rec = {
        "id": id,
        "min_hijack_ts": "2026-11-04T08:30:00Z",
        "max_hijack_ts": "2026-11-04T09:00:00Z",
        "hijacker_asn": 64500,
        "victim_asns": [13335, 15169],
        "victim_countries": ["US", "DE"],
        "hijacker_country": "RU",
        "confidence_score": 8,
    }
    rec.update(kw)
    return rec


def _env(**result):
    return {"success": True, "errors": [], "result": result}


def _norm(outages=(), hijacks=()):
    raw = {"outages": _env(annotations=list(outages)), "hijacks": _env(events=list(hijacks))}
    return CloudflareRadarCollector().normalize(raw).geo_events


def _stub(monkeypatch, outages=None, hijacks=None, seen=None):
    async def fake(url, **kw):
        if seen is not None:
            seen.append((url, kw))
        return outages if url == OUT_URL else hijacks

    monkeypatch.setattr(cfradar, "http_get_json", fake)


def _run(c=None):
    c = c or CloudflareRadarCollector()
    return c, asyncio.run(c.run())


def test_registration():
    assert REGISTRY["cf_radar"] is CloudflareRadarCollector
    assert CloudflareRadarCollector.cadence_seconds == 300


def test_no_token_no_calls(monkeypatch, caplog):
    monkeypatch.setattr(cfradar, "get_settings", lambda: SimpleNamespace(cf_radar_token=None))
    calls = []

    async def fake(url, **kw):
        calls.append(url)

    monkeypatch.setattr(cfradar, "http_get_json", fake)
    with caplog.at_level(logging.INFO):
        _, res = _run()
    assert calls == [] and res.geo_events == []
    assert caplog.text.count("CF_RADAR_TOKEN") == 1


def test_bearer_sent_to_both_and_never_logged(keyed, monkeypatch, caplog):
    seen = []
    _stub(monkeypatch, _env(annotations=[_outage()]), _env(events=[_hijack()]), seen)
    with caplog.at_level(logging.DEBUG):
        _, res = _run()
    assert [u for u, _ in seen] == [OUT_URL, BGP_URL]
    for _, kw in seen:
        assert kw["headers"]["Authorization"] == f"Bearer {TOKEN}"
        assert kw["max_bytes"] == 5_000_000
    assert seen[0][1]["params"] == {"dateRange": "7d", "format": "json", "limit": 100}
    assert seen[1][1]["params"] == {"dateRange": "7d", "format": "json", "per_page": 100}
    assert len(res.geo_events) == 4
    assert TOKEN not in caplog.text


def test_http_500_fails_run_without_token_in_logs(keyed, monkeypatch, caplog):
    async def fake(url, **kw):
        if url == BGP_URL:
            req = httpx.Request("GET", url)
            raise httpx.HTTPStatusError("500", request=req, response=httpx.Response(500, request=req))
        return _env(annotations=[_outage()])

    monkeypatch.setattr(cfradar, "http_get_json", fake)
    with caplog.at_level(logging.DEBUG):
        c, res = _run()
    assert c.last_error is not None and res.geo_events == []
    assert TOKEN not in caplog.text
    assert TOKEN not in repr(c.last_error) + str(c.last_error)
    assert TOKEN not in repr(c.__dict__)


@pytest.mark.parametrize("bad", [{"success": False, "errors": [{"code": 10000}]}, [], "x", None])
def test_unsuccessful_or_non_dict_fails_run(keyed, monkeypatch, bad):
    _stub(monkeypatch, bad, _env(events=[]))
    c, res = _run()
    assert c.last_error is not None and res.geo_events == []
    _stub(monkeypatch, _env(annotations=[]), bad)
    c, res = _run()
    assert c.last_error is not None and res.geo_events == []


def test_multi_country_outage():
    evs = _norm(outages=[_outage()])
    assert [e.external_id for e in evs] == ["out-1:IR", "out-1:IQ"]
    e = evs[0]
    assert (e.source, e.kind, e.country_code) == ("cf_radar", "outage", "IR")
    assert e.observed_at == FIXED_NOW  # ongoing: observed now, start kept in details
    assert e.magnitude == 3.0
    assert e.label == "GOVERNMENT_DIRECTED"
    assert e.details == {
        "cause": "GOVERNMENT_DIRECTED", "type": "NATIONWIDE", "scope": "Nationwide", "ongoing": True,
        "start": "2026-11-04T10:00:00+00:00",
    }


def test_outage_magnitude_capped_and_ended():
    rec = _outage(asns=list(range(50)), endDate="2026-11-04T12:00:00Z")
    e = _norm(outages=[rec])[0]
    assert e.magnitude == 10.0 and e.details["ongoing"] is False


def test_outage_locations_details_only():
    rec = _outage(details=[{"code": "ua", "name": "Ukraine"}, {"code": "PL"}])
    rec.pop("locations")
    evs = _norm(outages=[rec])
    assert [e.country_code for e in evs] == ["UA", "PL"]


def test_outage_dedupes_locations_across_sources():
    rec = _outage(locations=("IR",), details=[{"code": "IR"}])
    assert len(_norm(outages=[rec])) == 1


def test_outage_no_valid_location_emits_nothing():
    assert _norm(outages=[_outage(locations=(), details=[]), _outage(locations=("ZZZ", "1"))]) == []


def test_outage_invalid_code_skipped_valid_kept():
    evs = _norm(outages=[_outage(locations=("IR", "XYZ", ""))])
    assert [e.country_code for e in evs] == ["IR"]


def test_outage_label_fallbacks_and_truncation():
    rec = _outage(outage={}, scope="S" * 300)
    assert len(_norm(outages=[rec])[0].label) == 200
    rec = _outage(outage={}, scope=None, description="desc")
    assert _norm(outages=[rec])[0].label == "desc"


def test_hijack_one_event_per_victim_country():
    evs = _norm(hijacks=[_hijack()])
    assert [e.external_id for e in evs] == ["bgp:7:US", "bgp:7:DE"]
    e = evs[0]
    assert (e.kind, e.country_code, e.asn, e.magnitude) == ("bgp", "US", 64500, 8.0)
    assert e.label == "BGP hijack by AS64500"
    assert e.observed_at == datetime(2026, 11, 4, 8, 30, tzinfo=UTC)
    assert e.details == {"victim_asns": [13335, 15169], "confidence": 8}


def test_hijack_hijacker_country_fallback():
    e = _norm(hijacks=[_hijack(victim_countries=[])])
    assert [(x.country_code, x.external_id) for x in e] == [("RU", "bgp:7:RU")]


def test_hijack_no_country_single_event():
    evs = _norm(hijacks=[_hijack(victim_countries=[], hijacker_country=None)])
    assert len(evs) == 1 and evs[0].country_code is None
    assert evs[0].external_id == "bgp:7:-"


@pytest.mark.parametrize("score", [11, -1, float("nan"), float("inf"), "high", None, True])
def test_hijack_bad_confidence_defaults(score):
    assert _norm(hijacks=[_hijack(confidence_score=score)])[0].magnitude == 1.0


def test_hijack_bad_asn_is_none():
    assert _norm(hijacks=[_hijack(hijacker_asn=-5)])[0].asn is None


def test_malformed_records_skipped_others_kept():
    outs = [
        _outage(id="a"),
        "garbage",
        _outage(id="b", startDate="not a date"),
        _outage(id="c", locations=("FR",)),
    ]
    hij = [
        _hijack(id=1),
        None,
        _hijack(id=2, min_hijack_ts={}),
        _hijack(id=3, victim_countries=["US"]),
    ]
    evs = _norm(outages=outs, hijacks=hij)
    ids = [e.external_id for e in evs]
    assert ids == ["a:IR", "a:IQ", "c:FR", "bgp:1:US", "bgp:1:DE", "bgp:3:US"]


def test_epoch_and_z_timestamps():
    want = datetime(2026, 11, 4, 10, 0, tzinfo=UTC)
    z = _norm(outages=[_outage(startDate="2026-11-04T10:00:00Z", endDate=ENDED)])[0].observed_at
    off = _norm(outages=[_outage(startDate="2026-11-04T10:00:00+00:00", endDate=ENDED)])[0].observed_at
    epoch = _norm(outages=[_outage(startDate=1793786400, endDate=ENDED)])[0].observed_at
    assert z == off == epoch == want
    ms = _norm(hijacks=[_hijack(min_hijack_ts=1793786400000)])[0].observed_at
    assert ms == want
    assert _norm(hijacks=[_hijack(min_hijack_ts=1793786400.5)])[0].observed_at.year == 2026


@pytest.mark.parametrize("bad", [1e30, 10**25, -5, 0, float("inf"), float("nan"), 99999999999999999])
def test_absurd_epoch_skips_record_not_run(bad):
    evs = _norm(
        outages=[_outage(id="bad", startDate=bad), _outage(id="ok", locations=("FR",))],
        hijacks=[_hijack(id=1, min_hijack_ts=bad), _hijack(id=2, victim_countries=["US"])],
    )
    assert [e.external_id for e in evs] == ["ok:FR", "bgp:2:US"]


def test_absurd_epoch_does_not_fail_run(keyed, monkeypatch):
    _stub(monkeypatch, _env(annotations=[_outage(startDate=1e30)]), _env(events=[_hijack()]))
    c, res = _run()
    assert c.last_error is None and len(res.geo_events) == 2


@pytest.mark.parametrize("bad_id", [None, True, 1.5, [], {}, ""])
def test_invalid_record_id_skipped(bad_id):
    evs = _norm(outages=[_outage(id=bad_id)], hijacks=[_hijack(id=bad_id)])
    assert evs == []


def test_int_id_accepted():
    assert _norm(outages=[_outage(id=5, locations=("FR",))])[0].external_id == "5:FR"


def test_hijack_label_uses_validated_asn():
    assert _norm(hijacks=[_hijack(hijacker_asn=-5)])[0].label == "BGP hijack"
    assert _norm(hijacks=[_hijack(hijacker_asn="evil")])[0].label == "BGP hijack"


@pytest.mark.parametrize("score", [float("nan"), float("inf"), 11, "x"])
def test_hijack_details_confidence_validated(score):
    assert _norm(hijacks=[_hijack(confidence_score=score)])[0].details["confidence"] is None


def test_naive_timestamp_treated_as_utc():
    e = _norm(outages=[_outage(startDate="2026-11-04T10:00:00", endDate=ENDED)])[0]
    assert e.observed_at == datetime(2026, 11, 4, 10, 0, tzinfo=UTC)


def test_missing_result_sections_yield_nothing():
    raw = {"outages": {"success": True, "result": {}}, "hijacks": {"success": True, "result": {}}}
    assert CloudflareRadarCollector().normalize(raw).geo_events == []


def test_ongoing_outage_observed_now_with_start_in_details():
    three_days_ago = FIXED_NOW - timedelta(days=3)
    e = _norm(outages=[_outage(startDate=three_days_ago.isoformat())])[0]
    assert e.observed_at == FIXED_NOW
    assert e.details["ongoing"] is True
    assert e.details["start"] == three_days_ago.isoformat()


def test_ended_outage_keeps_start_date():
    e = _norm(outages=[_outage(startDate="2026-11-01T10:00:00Z", endDate=ENDED)])[0]
    assert e.observed_at == datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    assert e.details["start"] == "2026-11-01T10:00:00+00:00"


def test_external_id_same_for_ongoing_and_ended_run():
    ongoing = _norm(outages=[_outage(startDate="2026-11-01T10:00:00Z")])
    ended = _norm(outages=[_outage(startDate="2026-11-01T10:00:00Z", endDate=ENDED)])
    assert [e.external_id for e in ongoing] == [e.external_id for e in ended]


def test_disabled_message_logged_at_info_once(monkeypatch, caplog):
    monkeypatch.setattr(cfradar, "get_settings", lambda: SimpleNamespace(cf_radar_token=None))
    with caplog.at_level(logging.DEBUG, logger="cvenom.collectors.cfradar"):
        _run()
        _run()
    disabled = [r for r in caplog.records if "disabled" in r.getMessage()]
    assert [r.levelno for r in disabled] == [logging.INFO, logging.DEBUG]


def test_overlong_record_id_skips_only_that_record():
    evs = _norm(outages=[_outage(id="x" * 300), _outage(id="ok", locations=("FR",))])
    assert [e.external_id for e in evs] == ["ok:FR"]


def test_hijack_asn_over_32_bits_skips_only_that_record():
    evs = _norm(hijacks=[_hijack(id=1, hijacker_asn=2**40, victim_countries=["US"]),
                         _hijack(id=2, victim_countries=["US"])])
    assert [e.external_id for e in evs] == ["bgp:2:US"]
