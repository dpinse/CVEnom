import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import select

from cvenom.collectors import base, circl
from cvenom.collectors.base import REGISTRY
from cvenom.collectors.circl import (
    EVENT_URL,
    MANIFEST_URL,
    MAX_EVENT_BYTES,
    MAX_MANIFEST_BYTES,
    CirclOsintCollector,
)
from cvenom.models import Story
from cvenom.pipeline import ingest

FIX = Path(__file__).parent.parent / "fixtures"
U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
U3 = "33333333-3333-4333-8333-333333333333"


def _fx(name: str):
    return json.loads((FIX / name).read_text())


def _ev_fx(uuid: str):
    return _fx(f"circl_event_{uuid}.json")


def _uuid(i: int) -> str:
    return f"00000000-0000-4000-8000-{i:012x}"


def _event(uuid: str, ts: int, info="OSINT", cves=("CVE-2026-5001",)):
    return {
        "Event": {
            "uuid": uuid,
            "info": info,
            "timestamp": str(ts),
            "Attribute": [{"type": "vulnerability", "value": c} for c in cves],
        }
    }


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    calls = []

    async def fake(delay):
        calls.append(delay)

    monkeypatch.setattr(base, "_sleep", fake)
    return calls


def _mock_manifest(manifest: dict):
    return respx.get(MANIFEST_URL).mock(return_value=httpx.Response(200, json=manifest))


def _mock_events(events: dict):
    for uuid, ev in events.items():
        respx.get(EVENT_URL.format(uuid=uuid)).mock(return_value=httpx.Response(200, json=ev))


def _too_large(limit: int) -> httpx.Response:
    return httpx.Response(200, content=b"{}", headers={"Content-Length": str(limit + 1)})


def test_circl_registered_with_hourly_cadence():
    assert REGISTRY["circl_osint"] is CirclOsintCollector
    assert CirclOsintCollector.cadence_seconds == 3600


@respx.mock
async def test_circl_manifest_filters_newer_and_oldest_first(sleeps):
    manifest = _fx("circl_manifest.json")
    ts1 = manifest[U1]["timestamp"]
    _mock_manifest({**manifest, "not-a-uuid": {"timestamp": 1793300000}})
    _mock_events({u: _ev_fx(u) for u in (U2, U3)})
    col = CirclOsintCollector(state={"last_ts": ts1, "seen_at_last_ts": [U1]})
    raw = await col.fetch()
    assert [u for u, _ in raw] == [U2, U3]  # oldest first; U1 already seen at last_ts
    assert sleeps == [circl.REQUEST_DELAY]  # delay between event fetches only


@respx.mock
async def test_circl_same_timestamp_new_uuid_is_fetched():
    manifest = _fx("circl_manifest.json")
    last = manifest[U2]["timestamp"]
    manifest[U3]["timestamp"] = last  # a second event in the boundary second
    _mock_manifest(manifest)
    _mock_events({U2: _ev_fx(U2), U3: _ev_fx(U3)})
    col = CirclOsintCollector(state={"last_ts": last, "seen_at_last_ts": [U2]})
    raw = await col.fetch()
    assert [u for u, _ in raw] == [U3]
    res = col.normalize(raw)
    assert col.state["last_ts"] == last
    assert col.state["seen_at_last_ts"] == sorted([U2, U3])
    assert res.stories == []  # U3 names no CVEs


@respx.mock
async def test_circl_first_run_uses_7_day_window():
    now = int(datetime.now(UTC).timestamp())
    manifest = {
        _uuid(1): {"timestamp": now - 8 * 86400},
        _uuid(2): {"timestamp": now - 6 * 86400},
        _uuid(3): {"timestamp": now - 60},
    }
    _mock_manifest(manifest)
    _mock_events({_uuid(i): _event(_uuid(i), manifest[_uuid(i)]["timestamp"]) for i in (2, 3)})
    raw = await CirclOsintCollector().fetch()
    assert [u for u, _ in raw] == [_uuid(2), _uuid(3)]


@respx.mock
async def test_circl_caps_events_per_run_and_resumes():
    base_ts = int((datetime.now(UTC) - timedelta(days=1)).timestamp())
    manifest = {_uuid(i): {"timestamp": base_ts + i} for i in range(1, 61)}
    _mock_manifest(manifest)
    _mock_events({u: _event(u, m["timestamp"]) for u, m in manifest.items()})
    first = CirclOsintCollector()
    res = await first.run()
    assert first.last_error is None
    assert len(res.stories) == 50
    assert first.state["last_ts"] == base_ts + 50
    second = CirclOsintCollector(state=first.state)
    res2 = await second.run()
    assert len(res2.stories) == 10
    assert second.state["last_ts"] == base_ts + 60
    third = CirclOsintCollector(state=second.state)
    assert (await third.run()).stories == []


def test_circl_attribute_extraction_includes_objects():
    col = CirclOsintCollector()
    res = col.normalize([(U1, _ev_fx(U1)), (U2, _ev_fx(U2))])
    by_url = {s.url: s for s in res.stories}
    s1 = by_url[EVENT_URL.format(uuid=U1)]
    s2 = by_url[EVENT_URL.format(uuid=U2)]
    assert s1.summary == "Vulnerabilities: CVE-2026-5001"  # invalid value and URLs ignored
    assert s2.summary == "Vulnerabilities: CVE-2026-5002, CVE-2026-5003"  # object attrs only
    assert s1.source == "CIRCL OSINT" and s1.title == "OSINT with CVEs"
    assert s1.published == datetime.fromtimestamp(1793000000, UTC)
    assert col.state["last_ts"] == 1793100000


def test_circl_caps_cves_per_event():
    cves = [f"CVE-2026-{7000 + i}" for i in range(80)]
    res = CirclOsintCollector().normalize([(U1, _event(U1, 1793000000, cves=cves))])
    assert res.stories[0].summary.count("CVE-") == circl.MAX_CVES_PER_EVENT


def test_circl_event_without_vulns_skipped():
    col = CirclOsintCollector()
    res = col.normalize([(U3, _ev_fx(U3))])
    assert res.stories == []
    assert col.state["last_ts"] == 1793200000  # still counts as processed


@respx.mock
async def test_circl_invalid_uuid_never_fetched():
    now = int(datetime.now(UTC).timestamp())
    manifest = {
        "../../etc/passwd": {"timestamp": now},
        _uuid(10).upper(): {"timestamp": now},  # lowercase hex only
        "abc?x=1": {"timestamp": now},
        _uuid(2): {"timestamp": now},
    }
    _mock_manifest(manifest)
    _mock_events({_uuid(2): _event(_uuid(2), now)})
    raw = await CirclOsintCollector().fetch()
    assert [u for u, _ in raw] == [_uuid(2)]
    assert len(respx.calls) == 2  # manifest + the one valid event


@respx.mock
async def test_circl_oversize_manifest_fails_cleanly():
    respx.get(MANIFEST_URL).mock(return_value=_too_large(MAX_MANIFEST_BYTES))
    state = {"last_ts": 123, "seen_at_last_ts": ["x"]}
    col = CirclOsintCollector(state=state)
    res = await col.run()
    assert isinstance(col.last_error, base.ResponseTooLarge)
    assert res.stories == [] and col.state == state


@respx.mock
async def test_circl_oversize_event_is_skipped_but_advances():
    now = int(datetime.now(UTC).timestamp())
    manifest = {_uuid(1): {"timestamp": now - 10}, _uuid(2): {"timestamp": now - 5}}
    _mock_manifest(manifest)
    respx.get(EVENT_URL.format(uuid=_uuid(1))).mock(return_value=_too_large(MAX_EVENT_BYTES))
    _mock_events({_uuid(2): _event(_uuid(2), now - 5)})
    col = CirclOsintCollector()
    res = await col.run()
    assert col.last_error is None
    assert [s.url for s in res.stories] == [EVENT_URL.format(uuid=_uuid(2))]
    assert col.state["last_ts"] == now - 5


@respx.mock
async def test_circl_attribute_urls_never_requested():
    manifest = _fx("circl_manifest.json")
    _mock_manifest(manifest)
    _mock_events({U1: _ev_fx(U1)})  # its attributes hold attacker.invalid URLs
    manifest[U2]["timestamp"] = manifest[U3]["timestamp"] = 1  # old: only U1 is due
    _mock_manifest(manifest)
    col = CirclOsintCollector(state={"last_ts": manifest[U1]["timestamp"]})
    res = await col.run()
    assert len(res.stories) == 1
    called = {str(c.request.url) for c in respx.calls}
    assert called == {MANIFEST_URL, EVENT_URL.format(uuid=U1)}


@respx.mock
async def test_circl_story_title_sanitized_end_to_end(db_session):
    now = int(datetime.now(UTC).timestamp())
    _mock_manifest({_uuid(1): {"timestamp": now}})
    info = "<script>x()</script><b>Evil</b> &amp; co"
    _mock_events({_uuid(1): _event(_uuid(1), now, info=info)})
    res = await CirclOsintCollector().run()
    ingest(db_session, res, collector="circl_osint")
    story = db_session.scalars(select(Story).where(Story.source == "CIRCL OSINT")).one()
    assert "<" not in story.title and "script" not in story.title.lower()
    assert "Evil" in story.title
    assert story.summary == "Vulnerabilities: CVE-2026-5001"


@respx.mock
@pytest.mark.parametrize(
    "bad",
    [
        httpx.Response(404),
        httpx.Response(200, content=b"not json{"),
        httpx.Response(200, json=["not", "an", "object"]),
    ],
    ids=["404", "invalid-json", "non-dict"],
)
async def test_circl_poison_event_skipped_and_state_advances(bad):
    now = int(datetime.now(UTC).timestamp())
    manifest = {_uuid(1): {"timestamp": now - 10}, _uuid(2): {"timestamp": now - 5}}
    _mock_manifest(manifest)
    respx.get(EVENT_URL.format(uuid=_uuid(1))).mock(return_value=bad)
    _mock_events({_uuid(2): _event(_uuid(2), now - 5)})
    col = CirclOsintCollector()
    res = await col.run()
    assert col.last_error is None
    assert [s.url for s in res.stories] == [EVENT_URL.format(uuid=_uuid(2))]
    assert col.state["last_ts"] == now - 5


@respx.mock
async def test_circl_poison_event_alone_still_advances_state():
    now = int(datetime.now(UTC).timestamp())
    _mock_manifest({_uuid(1): {"timestamp": now - 10}})
    respx.get(EVENT_URL.format(uuid=_uuid(1))).mock(return_value=httpx.Response(404))
    col = CirclOsintCollector()
    assert (await col.run()).stories == []
    assert col.last_error is None and col.state["last_ts"] == now - 10


@respx.mock
@pytest.mark.parametrize(
    "failure",
    [httpx.Response(503), httpx.Response(429), httpx.Response(408), httpx.ConnectError("boom")],
    ids=["5xx", "429", "408", "transport"],
)
async def test_circl_server_or_transport_error_fails_run(failure):
    now = int(datetime.now(UTC).timestamp())
    _mock_manifest({_uuid(1): {"timestamp": now - 10}})
    route = respx.get(EVENT_URL.format(uuid=_uuid(1)))
    route.mock(side_effect=failure) if isinstance(failure, Exception) else route.mock(return_value=failure)
    state = {"last_ts": now - 100, "seen_at_last_ts": []}
    col = CirclOsintCollector(state=state)
    res = await col.run()
    assert col.last_error is not None
    assert res.stories == [] and col.state == state


@respx.mock
async def test_circl_far_future_manifest_timestamp_cannot_wedge_the_collector():
    now_ts = int(datetime.now(UTC).timestamp())
    manifest = {
        U1: {"timestamp": 9999999999},
        U2: {"timestamp": now_ts - 3600},
    }
    _mock_manifest(manifest)
    _mock_events({U2: _event(U2, now_ts - 3600)})
    c = CirclOsintCollector()
    res = await c.run()
    assert c.last_error is None
    assert [s.url for s in res.stories] == [EVENT_URL.format(uuid=U2)]
    assert c.state["last_ts"] == now_ts - 3600
