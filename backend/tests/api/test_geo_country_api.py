from datetime import UTC, datetime, timedelta

import pytest

from tests.api.test_read_api import (  # noqa: F401
    bearer, client, cve, geo, make_app, mk_user, secrets_key,
)


async def get(db, url, headers=None, **app_kw):
    async with client(make_app(db, **app_kw)) as c:
        return await c.get(url, headers=headers)


def _now():
    return datetime.now(UTC)


@pytest.mark.parametrize("cc", ["de", "DEU", "D1", "%00"])
async def test_country_invalid_codes_422(db_session, cc):
    r = await get(db_session, f"/api/geo/{cc}")
    assert r.status_code == 422


async def test_country_unknown_but_wellformed_is_empty_200(db_session):
    r = await get(db_session, "/api/geo/ZZ?window_hours=24")
    assert r.status_code == 200
    d = r.json()
    assert d["country_code"] == "ZZ" and d["window_hours"] == 24
    assert d["counts"] == [] and d["top_sources"] == []
    assert d["events"] is None
    assert len(d["trend"]) == 24 and all(p["events"] == 0 for p in d["trend"])


async def test_country_counts_and_top_sources(db_session):
    for i in range(6):
        for j in range(i + 1):
            geo(db_session, f"s{i}-{j}", source=f"src{i}", kind="outage", country_code="DE",
                magnitude=2.0)
    geo(db_session, "o1", source="src0", kind="attack", country_code="DE", magnitude=3.0)
    geo(db_session, "other", country_code="FR")
    d = (await get(db_session, "/api/geo/DE")).json()
    by_kind = {c["kind"]: c for c in d["counts"]}
    assert by_kind["outage"] == {"kind": "outage", "events": 21, "magnitude": 42.0}
    assert by_kind["attack"] == {"kind": "attack", "events": 1, "magnitude": 3.0}
    assert [c["kind"] for c in d["counts"]] == ["outage", "attack"]
    assert len(d["top_sources"]) == 5
    assert d["top_sources"][0] == {"source": "src5", "events": 6}
    assert [s["events"] for s in d["top_sources"]] == sorted(
        (s["events"] for s in d["top_sources"]), reverse=True
    )


async def test_country_trend_zero_filled_length(db_session):
    geo(db_session, "t1", country_code="DE", observed_at=_now() - timedelta(hours=2))
    geo(db_session, "t2", country_code="DE", observed_at=_now() - timedelta(hours=2))
    geo(db_session, "old", country_code="DE", observed_at=_now() - timedelta(hours=30))
    d = (await get(db_session, "/api/geo/DE?window_hours=24")).json()
    t = d["trend"]
    assert len(t) == 24
    buckets = [datetime.fromisoformat(p["bucket"]) for p in t]
    assert buckets == sorted(buckets)
    assert all(b.minute == 0 and b.second == 0 for b in buckets)
    assert sum(p["events"] for p in t) == 2
    assert sum(1 for p in t if p["events"]) == 1


async def test_country_anon_events_null_but_victim_count_public(db_session):
    geo(db_session, "n1", country_code="CA", kind="outage")
    geo(db_session, "v1", source="ransomware_live", kind="victim", country_code="CA",
        label="Zyxwv Victim", magnitude=1.0)
    r = await get(db_session, "/api/geo/CA")
    d = r.json()
    assert d["events"] is None
    assert {c["kind"]: c["events"] for c in d["counts"]} == {"outage": 1, "victim": 1}
    assert "ransomware_live" in {s["source"] for s in d["top_sources"]}
    assert "Zyxwv" not in r.text


async def test_country_authed_events_capped_50_newest_first_include_ransomware(db_session):
    base = _now() - timedelta(hours=1)
    for i in range(55):
        geo(db_session, f"e{i}", country_code="CA", observed_at=base - timedelta(seconds=i),
            label=f"l{i}")
    geo(db_session, "v1", source="ransomware_live", kind="victim", country_code="CA",
        label="Zyxwv Victim", observed_at=base + timedelta(seconds=5), story_url="https://x.test/v")
    h, _ = bearer(db_session, mk_user(db_session))
    d = (await get(db_session, "/api/geo/CA", headers=h)).json()
    ev = d["events"]
    assert len(ev) == 50
    assert ev[0]["label"] == "Zyxwv Victim" and ev[0]["source"] == "ransomware_live"
    assert set(ev[0]) == {"source", "kind", "label", "magnitude", "observed_at", "asn",
                          "story_url", "details"}
    times = [e["observed_at"] for e in ev]
    assert times == sorted(times, reverse=True)
    assert sum(c["events"] for c in d["counts"]) == 56


async def test_country_anon_second_call_cache_hit_and_authed_bypasses(db_session):
    geo(db_session, "v1", source="ransomware_live", kind="victim", country_code="CA",
        label="Zyxwv Victim")
    app = make_app(db_session)
    async with client(app) as c:
        r1 = await c.get("/api/geo/CA?window_hours=24")
        r2 = await c.get("/api/geo/CA?window_hours=24")
        assert r1.headers["x-cache"] == "MISS" and r2.headers["x-cache"] == "HIT"
        assert r2.json()["events"] is None and "Zyxwv" not in r2.text
        h, _ = bearer(db_session, mk_user(db_session))
        r3 = await c.get("/api/geo/CA?window_hours=24", headers=h)
        assert "x-cache" not in r3.headers
        assert r3.json()["events"][0]["label"] == "Zyxwv Victim"


@pytest.mark.parametrize("w", [0, 169])
async def test_country_window_bounds_422(db_session, w):
    r = await get(db_session, f"/api/geo/DE?window_hours={w}")
    assert r.status_code == 422


async def test_geo_country_range_daily_trend(db_session):
    geo(db_session, "d1", country_code="DE", observed_at=_now() - timedelta(days=10))
    geo(db_session, "d2", country_code="DE", observed_at=_now())
    d = (await get(db_session, "/api/geo/DE?range=14d")).json()
    assert d["window_hours"] == 336
    assert d["trend_unit"] == "day" and len(d["trend"]) == 14
    buckets = [datetime.fromisoformat(p["bucket"]) for p in d["trend"]]
    assert all(b.hour == 0 and b.minute == 0 for b in buckets) and buckets == sorted(buckets)
    assert sum(p["events"] for p in d["trend"]) == 2
    assert d["trend"][-1]["events"] >= 1
    h = (await get(db_session, "/api/geo/DE?range=24h")).json()
    assert h["trend_unit"] == "hour" and len(h["trend"]) == 24
    w = (await get(db_session, "/api/geo/DE?range=7d")).json()
    assert w["trend_unit"] == "hour" and len(w["trend"]) == 168
    assert (await get(db_session, "/api/geo/DE")).json()["trend_unit"] == "hour"


async def test_geo_country_top_cves(db_session):
    cve(db_session, "CVE-2024-0001", cvss=9.8)
    cve(db_session, "CVE-2024-0002")
    for i in range(3):
        geo(db_session, f"a{i}", country_code="DE", cve_id="CVE-2024-0001")
    geo(db_session, "b0", country_code="DE", cve_id="CVE-2024-0002")
    geo(db_session, "none", country_code="DE")
    geo(db_session, "other", country_code="FR", cve_id="CVE-2024-0002")
    for i in range(5):  # more than 5 distinct ids: capped
        geo(db_session, f"x{i}", country_code="DE", cve_id=f"CVE-2024-90{i}0")
    d = (await get(db_session, "/api/geo/DE")).json()
    assert len(d["top_cves"]) == 5
    assert d["top_cves"][0] == {"cve_id": "CVE-2024-0001", "cvss": 9.8, "events": 3}
    assert all(t["events"] == 1 for t in d["top_cves"][1:])
    assert {"cve_id": "CVE-2024-0002", "cvss": None, "events": 1} in d["top_cves"]


async def test_geo_country_anon_events_null_with_range(db_session):
    geo(db_session, "v1", source="ransomware_live", kind="victim", country_code="CA",
        label="Zyxwv Victim", magnitude=1.0, observed_at=_now() - timedelta(days=20))
    r = await get(db_session, "/api/geo/CA?range=30d")
    d = r.json()
    assert d["events"] is None
    assert "Zyxwv" not in r.text
    assert d["counts"] == [{"kind": "victim", "events": 1, "magnitude": 1.0}]
