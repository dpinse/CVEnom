import base64
import os
from datetime import UTC, date, datetime, timedelta

from contextlib import contextmanager

import fakeredis
import httpx
import pytest
from sqlalchemy import event

from cvenom.api import create_app
from cvenom.auth.passwords import hash_password
from cvenom.auth.tokens import create_session, issue_access
from cvenom.config import get_settings
from cvenom.models import Cve, GeoEvent, Story, StoryCveLink, User



def make_app(db_session, redis=None, **overrides):
    settings = get_settings().model_copy(update=overrides)

    @contextmanager
    def factory():
        yield db_session

    return create_app(
        settings, redis=redis or fakeredis.FakeAsyncRedis(), session_factory=factory
    )


def client(app, peer=("1.2.3.4", 1234)):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=peer), base_url="https://test"
    )


def mk_user(db):
    u = User(email="u@example.com", password_hash=hash_password("correct horse battery"),
             role="member", is_active=True)
    db.add(u)
    db.flush()
    return u


def bearer(db, user):
    now = datetime.now(UTC)
    row, _ = create_session(db, user, now, "ua", "9.9.9.9")
    return {"Authorization": f"Bearer {issue_access(db, user, row.id, now)}"}, row

NOW = datetime.now(UTC)
LANE_KEYS = {
    "cve_id", "cvss", "epss_percentile", "kev", "kev_added", "kev_source", "poc_badge",
    "patch_available", "published", "summary", "recent_story_count", "product", "last_seen",
}
GEO_EVENT_KEYS = {"kind", "country_code", "label", "magnitude", "observed_at", "details"}


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def cve(db, cve_id, **kw):
    kw.setdefault("published", NOW - timedelta(days=100))
    kw.setdefault("summary", "s")
    c = Cve(cve_id=cve_id, **kw)
    db.add(c)
    db.flush()
    return c


def story(db, n, cve_ids=(), published=None, title="t"):
    s = Story(
        url=f"https://ex.test/{n}", content_hash=f"h{n}", source="src", title=title,
        summary="x", published=published or NOW - timedelta(hours=1),
    )
    db.add(s)
    db.flush()
    for cid in cve_ids:
        db.add(StoryCveLink(story_id=s.id, cve_id=cid))
    db.flush()
    return s


def geo(db, ext, **kw):
    kw.setdefault("source", "s")
    kw.setdefault("kind", "outage")
    kw.setdefault("observed_at", NOW)
    kw.setdefault("country_code", "US")
    e = GeoEvent(external_id=ext, **kw)
    db.add(e)
    db.flush()
    return e


async def get(db, url, headers=None, **app_kw):
    async with client(make_app(db, **app_kw)) as c:
        return await c.get(url, headers=headers)


# ---------------------------------------------------------------- lanes


async def test_lanes_shape_and_keys(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=NOW.date(), kev_source="cisa",
        cvss=9.8, summary="&lt;b&gt;")
    cve(db_session, "CVE-2024-0002", epss_percentile=0.99, published=NOW - timedelta(days=5))
    cve(db_session, "CVE-2024-0003")
    story(db_session, 1, ["CVE-2024-0003"])
    cve(db_session, "CVE-2024-0004", cvss=9.5, published=NOW - timedelta(hours=2))
    r = await get(db_session, "/api/lanes")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"EXPLOITED", "LIKELY", "LOUD", "FRESH"}
    for lane, expect in [("EXPLOITED", "CVE-2024-0001"), ("LIKELY", "CVE-2024-0002"),
                         ("LOUD", "CVE-2024-0003"), ("FRESH", "CVE-2024-0004")]:
        assert body[lane]["total"] == 1
        assert [i["cve_id"] for i in body[lane]["items"]] == [expect]
        assert set(body[lane]["items"][0]) == LANE_KEYS
    ex = body["EXPLOITED"]["items"][0]
    assert ex["kev_added"] == NOW.date().isoformat() and ex["kev_source"] == "cisa"
    assert ex["summary"] == "&lt;b&gt;"  # returned as stored, not unescaped
    assert body["LOUD"]["items"][0]["recent_story_count"] == 1


async def test_lanes_cap_100(db_session):
    for i in range(105):
        cve(db_session, f"CVE-2024-{1000 + i}", kev=True, kev_added=NOW.date())
    r = await get(db_session, "/api/lanes?limit=100")
    ex = r.json()["EXPLOITED"]
    assert len(ex["items"]) == 100 and ex["total"] == 105
    assert (await get(db_session, "/api/lanes?limit=101")).status_code == 422


async def test_lanes_no_n_plus_one(db_session):
    for i in range(6):
        cve(db_session, f"CVE-2024-{2000 + i}", kev=True, kev_added=NOW.date(), epss_percentile=0.99, cvss=9.9,
            published=NOW - timedelta(hours=1))
        story(db_session, 100 + i, [f"CVE-2024-{2000 + i}"])
        cve(db_session, f"CVE-2024-{2100 + i}", epss_percentile=0.99, cvss=9.9,
            published=NOW - timedelta(hours=1))
    stmts = []

    def count(conn, cursor, statement, *a):
        stmts.append(statement)

    engine = db_session.get_bind()
    event.listen(engine, "before_cursor_execute", count)
    try:
        r = await get(db_session, "/api/lanes?limit=10")
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert r.status_code == 200
    body = r.json()
    assert {k: len(v["items"]) for k, v in body.items()} == {
        "EXPLOITED": 6, "LIKELY": 6, "LOUD": 6, "FRESH": 6,
    }
    assert len(stmts) <= 4, stmts


async def test_lanes_second_anonymous_call_is_cache_hit(db_session):
    cve(db_session, "CVE-2024-0001", kev=True)
    async with client(make_app(db_session)) as c:
        r1 = await c.get("/api/lanes")
        r2 = await c.get("/api/lanes")
    assert r1.headers["x-cache"] == "MISS"
    assert r2.headers["x-cache"] == "HIT"
    assert r1.json() == r2.json()


async def test_summary_cached_for_anon(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=NOW.date())
    async with client(make_app(db_session)) as c:
        r1 = await c.get("/api/summary?range=7d")
        r2 = await c.get("/api/summary?range=7d")
    assert r1.headers["x-cache"] == "MISS"
    assert r2.headers["x-cache"] == "HIT"
    assert r1.json() == r2.json()
    b = r1.json()
    assert b["range"] == "7d" and b["new_kev"] == 1
    assert b["latest_kev_added"] == NOW.date().isoformat()
    assert set(b) == {
        "range", "new_kev", "kev_due_soon", "new_critical", "public_exploits", "latest_kev_added",
    }


async def test_volume_endpoint_shape(db_session):
    cve(db_session, "CVE-2024-0001", cvss=9.8, published=NOW)
    cve(db_session, "CVE-2024-0002", published=NOW)
    b = (await get(db_session, "/api/volume?range=7d")).json()
    assert b["unit"] == "day" and len(b["buckets"]) == 7
    assert b["buckets"][-1]["crit"] == 1 and b["total"] == 1 and b["unscored"] == 1
    assert set(b["buckets"][0]) == {"start", "crit", "high", "med", "low"}
    h = (await get(db_session, "/api/volume?range=24h")).json()
    assert h["unit"] == "hour" and len(h["buckets"]) == 24


async def test_summary_and_volume_invalid_range_422(db_session):
    for path in ("/api/summary", "/api/volume"):
        for rng in ("1y", "", "7D"):
            assert (await get(db_session, f"{path}?range={rng}")).status_code == 422, (path, rng)


async def test_geo_range_30d_includes_29_day_old_event(db_session):
    geo(db_session, "old", country_code="FR", observed_at=NOW - timedelta(days=29))
    geo(db_session, "older", country_code="DE", observed_at=NOW - timedelta(days=31))
    assert (await get(db_session, "/api/geo")).json() == []
    rows = (await get(db_session, "/api/geo?range=30d")).json()
    assert [r["country_code"] for r in rows] == ["FR"]
    # range wins over window_hours
    rows = (await get(db_session, "/api/geo?range=30d&window_hours=1")).json()
    assert [r["country_code"] for r in rows] == ["FR"]
    assert (await get(db_session, "/api/geo?range=1y")).status_code == 422
    assert (await get(db_session, "/api/geo?window_hours=169")).status_code == 422


async def test_search_and_detail_not_cached(db_session):
    cve(db_session, "CVE-2024-0001")
    async with client(make_app(db_session)) as c:
        for url in ("/api/cves", "/api/cves/CVE-2024-0001"):
            await c.get(url)
            r = await c.get(url)
            assert "x-cache" not in r.headers


# ---------------------------------------------------------------- auth


async def test_public_read_off_requires_auth(db_session):
    u = mk_user(db_session)
    h, _ = bearer(db_session, u)
    for url in (
        "/api/lanes", "/api/cves", "/api/velocity", "/api/geo", "/api/stories/loud",
        "/api/summary", "/api/volume",
    ):
        anon = await get(db_session, url, public_read=False)
        assert anon.status_code == 401, url
        ok = await get(db_session, url, headers=h, public_read=False)
        assert ok.status_code == 200, url


# ---------------------------------------------------------------- detail


async def test_detail(db_session):
    cve(db_session, "CVE-2024-0001", epss=0.5, affected=[{"vendor": "v"}], kev=True)
    for i in range(55):
        story(db_session, i, ["CVE-2024-0001"], published=NOW - timedelta(minutes=i + 1),
              title=f"T{i}")
    for i in range(105):
        geo(db_session, f"x{i}", cve_id="CVE-2024-0001", asn=64512, story_url="https://s.test",
            label=f"L{i}", observed_at=NOW - timedelta(minutes=i), details={"k": 1})
    geo(db_session, "other", cve_id="CVE-2024-9999")
    r = await get(db_session, "/api/cves/CVE-2024-0001")
    assert r.status_code == 200
    b = r.json()
    assert set(b) == LANE_KEYS | {
        "epss", "affected", "events", "related", "affected_versions", "geo_top",
        "updated_at", "stories", "geo_events", "kev_name", "kev_action", "kev_notes",
        "kev_due", "kev_ransomware", "cvss_vector", "cvss_severity", "cwes", "references",
        "last_modified",
    }
    assert b["epss"] == 0.5 and b["affected"] == [{"vendor": "v"}]
    assert len(b["stories"]) == 50 and b["stories"][0]["title"] == "T0"
    assert set(b["stories"][0]) == {"title", "url", "source", "published"}
    assert len(b["geo_events"]) == 100 and b["geo_events"][0]["label"] == "L0"
    assert set(b["geo_events"][0]) == GEO_EVENT_KEYS
    assert "external_id" not in r.text and "64512" not in r.text


@pytest.mark.parametrize(
    "path",
    ["../../etc", "..%2F..%2Fetc", "cve-2024-0001", "CVE-2024-0001%20", "CVE-24-1",
     "CVE-2024-9999", "CVE-2024-0001/x"],
)
async def test_detail_not_found(db_session, path):
    cve(db_session, "CVE-2024-0001")
    r = await get(db_session, f"/api/cves/{path}")
    assert r.status_code == 404
    if path != "../../etc":  # httpx collapses raw dot-segments before the app sees them
        assert r.json() == {"error": "not_found"}


# ---------------------------------------------------------------- search


async def test_search_basic_and_filters(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=NOW.date(), kev_source="cisa", cvss=9.0,
        published=NOW - timedelta(days=1), summary="Apache thing")
    cve(db_session, "CVE-2024-0002", kev=True, kev_added=NOW.date(), kev_source="vulncheck", cvss=5.0,
        published=NOW - timedelta(days=200), summary="nginx")
    cve(db_session, "CVE-2024-0003", cvss=7.0, published=None)
    story(db_session, 1, ["CVE-2024-0001"])

    async def ids(qs):
        r = await get(db_session, "/api/cves" + qs)
        assert r.status_code == 200, r.text
        return [i["cve_id"] for i in r.json()["items"]]

    assert await ids("") == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]  # NULLS LAST
    assert await ids("?q=apache") == ["CVE-2024-0001"]
    assert await ids("?q=cve-2024-0002") == ["CVE-2024-0002"]
    assert await ids("?source=vulncheck") == ["CVE-2024-0002"]
    assert await ids("?min_cvss=7") == ["CVE-2024-0001", "CVE-2024-0003"]
    assert await ids("?kev=true") == ["CVE-2024-0001", "CVE-2024-0002"]
    assert await ids("?kev=false") == ["CVE-2024-0003"]
    assert await ids("?lane=LOUD") == ["CVE-2024-0001"]
    assert await ids("?lane=EXPLOITED") == ["CVE-2024-0001", "CVE-2024-0002"]
    frm = (NOW - timedelta(days=2)).date().isoformat()
    assert await ids(f"?from={frm}") == ["CVE-2024-0001"]
    to = (NOW - timedelta(days=100)).date().isoformat()
    assert await ids(f"?to={to}") == ["CVE-2024-0002"]
    r = await get(db_session, "/api/cves")
    b = r.json()
    assert set(b) == {
        "items", "page", "page_size", "total", "exact_match", "exact_match_filtered_out",
    } and b["total"] == 3
    assert set(b["items"][0]) == LANE_KEYS
    assert b["items"][0]["recent_story_count"] == 1


async def test_search_like_escaping(db_session):
    cve(db_session, "CVE-2024-0001", summary="100% sure")
    cve(db_session, "CVE-2024-0002", summary="snake_case")
    cve(db_session, "CVE-2024-0003", summary="plain text")
    cve(db_session, "CVE-2024-0004", summary="back\\slash")

    async def ids(q):
        async with client(make_app(db_session)) as c:
            r = await c.get("/api/cves", params={"q": q})
        assert r.status_code == 200
        return sorted(i["cve_id"] for i in r.json()["items"])

    assert await ids("%") == ["CVE-2024-0001"]
    assert await ids("_") == ["CVE-2024-0002"]
    assert await ids("\\") == ["CVE-2024-0004"]


async def test_search_validation(db_session):
    for qs in (
        "?q=" + "a" * 5000, "?page_size=101", "?page_size=0", "?page=0", "?page=10001",
        "?min_cvss=11", "?min_cvss=-1", "?source=other", "?lane=NOPE", "?from=notadate",
        "?kev=maybe",
    ):
        r = await get(db_session, "/api/cves" + qs)
        assert r.status_code == 422, qs
    assert (await get(db_session, "/api/cves?q=" + "a" * 200)).status_code == 200


async def test_search_non_utf8_query_is_422(db_session):
    for path in ("/api/cves?q=%FF", "/api/velocity?days=%FF", "/api/lanes?x=%C3%28"):
        r = await get(db_session, path)
        assert r.status_code == 422, path
        assert r.json() == {"error": "validation_error"}
    assert (await get(db_session, "/api/cves?q=%C3%A9")).status_code == 200


async def test_search_pagination_and_stable_order(db_session):
    same = NOW - timedelta(days=3)
    for i in range(5):
        cve(db_session, f"CVE-2024-{3000 + i}", published=same)
    seen = []
    async with client(make_app(db_session)) as c:
        for p in (1, 2, 3):
            r = await c.get("/api/cves", params={"page": p, "page_size": 2})
            b = r.json()
            assert b["total"] == 5 and b["page"] == p and b["page_size"] == 2
            seen += [i["cve_id"] for i in b["items"]]
        assert len((await c.get("/api/cves", params={"page": 4, "page_size": 2})).json()["items"]) == 0
    assert seen == [f"CVE-2024-{3000 + i}" for i in range(5)]


# ---------------------------------------------------------------- velocity / geo / stories


async def test_velocity(db_session):
    cve(db_session, "CVE-2024-0001", published=NOW)
    r = await get(db_session, "/api/velocity")
    assert r.status_code == 200
    b = r.json()
    assert set(b) == {"series", "current", "rising"}
    assert len(b["series"]) == 30 and b["current"] == 1
    assert set(b["series"][0]) == {"day", "count"}
    assert len((await get(db_session, "/api/velocity?days=7")).json()["series"]) == 7
    for d in ("0", "31", "-1", "x"):
        assert (await get(db_session, f"/api/velocity?days={d}")).status_code == 422


async def test_geo(db_session):
    geo(db_session, "a", country_code="US", magnitude=2.0, asn=1, story_url="https://u.test")
    geo(db_session, "b", country_code="US", magnitude=3.0)
    geo(db_session, "c", country_code="DE", kind="bgp")
    geo(db_session, "old", country_code="FR", observed_at=NOW - timedelta(hours=100))
    r = await get(db_session, "/api/geo")
    assert r.status_code == 200
    items = r.json()
    assert {(i["country_code"], i["kind"]) for i in items} == {("US", "outage"), ("DE", "bgp")}
    assert items[0]["country_code"] == "US" and items[0]["magnitude"] == 5.0
    assert items[0]["events"] == 2
    assert set(items[0]) == {"country_code", "kind", "magnitude", "events", "last_seen"}
    assert "external_id" not in r.text and "asn" not in r.text
    assert len((await get(db_session, "/api/geo?window_hours=168")).json()) == 3
    for w in ("0", "169"):
        assert (await get(db_session, f"/api/geo?window_hours={w}")).status_code == 422


async def test_loud_stories(db_session):
    cve(db_session, "CVE-2024-0001")
    for i in range(3):
        story(db_session, i, ["CVE-2024-0001"], published=NOW - timedelta(minutes=i + 1))
    r = await get(db_session, "/api/stories/loud?limit=2")
    assert r.status_code == 200
    b = r.json()
    assert len(b) == 2
    assert set(b[0]) == {"title", "summary", "url", "source", "published", "cve_ids"}
    assert b[0]["cve_ids"] == ["CVE-2024-0001"]
    for lim in ("0", "101"):
        assert (await get(db_session, f"/api/stories/loud?limit={lim}")).status_code == 422
    assert len((await get(db_session, "/api/stories/loud")).json()) == 3


async def test_default_cache_paths_applied_and_explicit_respected(db_session):
    app = create_app(
        get_settings(), redis=fakeredis.FakeAsyncRedis(), cache_paths={},
        session_factory=make_app(db_session).state.session_factory,
    )
    async with client(app) as c:
        await c.get("/api/lanes")
        assert "x-cache" not in (await c.get("/api/lanes")).headers


# ---------------------------------------------------------------- fix round 1


@pytest.mark.parametrize("qs", ["?q=%00", "?q=a%00b", "?page=%001"])
async def test_nul_byte_is_422(db_session, qs):
    r = await get(db_session, "/api/cves" + qs)
    assert r.status_code == 422
    assert r.json() == {"error": "validation_error"}


async def test_q_plus_and_percent2b(db_session):
    cve(db_session, "CVE-2024-0001", summary="a b")
    cve(db_session, "CVE-2024-0002", summary="a+b")
    r = await get(db_session, "/api/cves?q=a+b")
    assert [i["cve_id"] for i in r.json()["items"]] == ["CVE-2024-0001"]
    r = await get(db_session, "/api/cves?q=a%2Bb")
    assert [i["cve_id"] for i in r.json()["items"]] == ["CVE-2024-0002"]


async def test_date_edge_cases(db_session):
    cve(db_session, "CVE-2024-0001", published=NOW - timedelta(days=3))
    r = await get(db_session, "/api/cves?from=2030-01-02&to=2030-01-01")
    assert r.status_code == 200 and r.json()["items"] == [] and r.json()["total"] == 0
    r = await get(db_session, "/api/cves?from=0001-01-01")
    assert r.status_code == 200 and r.json()["total"] == 1
    r = await get(db_session, "/api/cves?to=9999-12-31")
    assert r.status_code == 200 and r.json()["total"] == 1
    day = (NOW - timedelta(days=3)).date().isoformat()
    r = await get(db_session, f"/api/cves?from={day}&to={day}")
    assert r.json()["total"] == 1


@pytest.mark.parametrize("v", ["nan", "inf", "-inf"])
async def test_min_cvss_non_finite(db_session, v):
    assert (await get(db_session, f"/api/cves?min_cvss={v}")).status_code == 422


async def test_cves_trailing_slash_404(db_session):
    r = await get(db_session, "/api/cves/")
    assert r.status_code == 404


async def test_lane_filter_large_membership(db_session):
    for i in range(300):
        cve(db_session, f"CVE-2024-{5000 + i}", kev=True, kev_added=NOW.date())
    r = await get(db_session, "/api/cves?lane=EXPLOITED&page_size=100")
    assert r.status_code == 200 and r.json()["total"] == 300


async def test_datetimes_serialized_utc(db_session):
    from datetime import timezone

    tz = timezone(timedelta(hours=5))
    pub = datetime(2024, 3, 1, 12, 0, tzinfo=tz)
    cve(db_session, "CVE-2024-0001", published=pub)
    story(db_session, 1, ["CVE-2024-0001"], published=pub)
    geo(db_session, "g", cve_id="CVE-2024-0001", observed_at=pub)
    for url in ("/api/cves", "/api/cves/CVE-2024-0001"):
        r = await get(db_session, url)
        b = r.json()
        item = b["items"][0] if "items" in b else b
        assert item["published"] in ("2024-03-01T07:00:00Z", "2024-03-01T07:00:00+00:00")
    d = (await get(db_session, "/api/cves/CVE-2024-0001")).json()
    assert d["stories"][0]["published"].startswith("2024-03-01T07:00:00")
    assert d["geo_events"][0]["observed_at"].startswith("2024-03-01T07:00:00")
    assert d["stories"][0]["published"].endswith(("Z", "+00:00"))


# ------------------------------------------------ ransomware.live fair use


def _rl_fixture(db):
    cve(db, "CVE-2024-7777")
    s = story(db, 900, ["CVE-2024-7777"], title="Victim Inc listed by grp")
    s.source = "ransomware.live"
    story(db, 901, ["CVE-2024-7777"], title="normal news")
    geo(db, "rl1", source="ransomware_live", kind="victim", cve_id="CVE-2024-7777",
        label="grp: Victim Inc", country_code="CA", magnitude=1.0)
    db.flush()


async def test_loud_ransomware_anon_excluded_authed_included(db_session):
    _rl_fixture(db_session)
    anon = await get(db_session, "/api/stories/loud")
    assert {b["source"] for b in anon.json()} == {"src"}
    assert "Victim Inc" not in anon.text
    h, _ = bearer(db_session, mk_user(db_session))
    authed = await get(db_session, "/api/stories/loud", headers=h)
    assert "ransomware.live" in {b["source"] for b in authed.json()}


async def test_geo_ransomware_aggregate_visible_without_details(db_session):
    _rl_fixture(db_session)
    r = await get(db_session, "/api/geo")
    row = next(i for i in r.json() if i["kind"] == "victim")
    assert row["country_code"] == "CA" and row["events"] == 1
    assert set(row) == {"country_code", "kind", "magnitude", "events", "last_seen"}
    assert "Victim Inc" not in r.text


async def test_detail_ransomware_anon_excluded_authed_included(db_session):
    _rl_fixture(db_session)
    anon = (await get(db_session, "/api/cves/CVE-2024-7777")).json()
    assert [s["source"] for s in anon["stories"]] == ["src"]
    assert anon["geo_events"] == []
    h, _ = bearer(db_session, mk_user(db_session))
    authed = (await get(db_session, "/api/cves/CVE-2024-7777", headers=h)).json()
    assert {s["source"] for s in authed["stories"]} == {"src", "ransomware.live"}
    assert [g["label"] for g in authed["geo_events"]] == ["grp: Victim Inc"]
    assert anon["recent_story_count"] == 1  # restricted story not counted for anonymous
    assert authed["recent_story_count"] == 2


async def test_public_read_off_everyone_authed_sees_ransomware(db_session):
    _rl_fixture(db_session)
    h, _ = bearer(db_session, mk_user(db_session))
    r = await get(db_session, "/api/stories/loud", headers=h, public_read=False)
    assert "ransomware.live" in {b["source"] for b in r.json()}
    assert (await get(db_session, "/api/stories/loud", public_read=False)).status_code == 401


async def test_anon_cached_loud_has_no_ransomware_authed_does(db_session):
    _rl_fixture(db_session)
    app = make_app(db_session)
    async with client(app) as c:
        r1 = await c.get("/api/stories/loud")
        r2 = await c.get("/api/stories/loud")
        assert r1.headers["x-cache"] == "MISS" and r2.headers["x-cache"] == "HIT"
        assert "Victim Inc" not in r2.text
        h, _ = bearer(db_session, mk_user(db_session))
        r3 = await c.get("/api/stories/loud", headers=h)
        assert "x-cache" not in r3.headers
        assert "Victim Inc" in r3.text


_RL_MARK = "Zyxwv Victim Holdings"


def _rl_marked_fixture(db):
    """A ransomware.live victim story and victim geo event with a distinctive name, linked
    to a KEV CVE that the lanes surface (exploited) and that search finds."""
    cve(db, "CVE-2024-8888", kev=True, kev_added=NOW.date(), cvss=9.8,
        published=NOW - timedelta(days=1), summary="gateway flaw")
    s = story(db, 950, ["CVE-2024-8888"], title=f"{_RL_MARK} listed by grp")
    s.source = "ransomware.live"
    geo(db, "rl-mark", source="ransomware_live", kind="victim", cve_id="CVE-2024-8888",
        label=f"grp: {_RL_MARK}", country_code="CA", magnitude=1.0)
    db.flush()


async def test_c5_anon_search_and_lanes_never_carry_ransomware_victims(db_session):
    """Compliance regression guard: no anonymous read (search, lanes, their anonymous cache,
    or the other public reads) may ever contain ransomware.live victim data."""
    _rl_marked_fixture(db_session)
    app = make_app(db_session)
    async with client(app) as c:
        paths = [
            "/api/lanes",
            "/api/cves",
            "/api/cves?q=CVE-2024-8888",
            "/api/cves?q=Zyxwv",
            "/api/cves?kev=true",
            "/api/velocity",
            "/api/geo",
            "/api/stories/loud",
            "/api/cves/CVE-2024-8888",
        ]
        for path in paths:
            r = await c.get(path)
            assert r.status_code == 200, path
            assert _RL_MARK not in r.text, path
        # the anonymous cache path: a second hit is served from cache and is still clean
        hit = await c.get("/api/lanes")
        assert hit.headers["x-cache"] == "HIT"
        assert _RL_MARK not in hit.text
        lane_ids = {i["cve_id"] for lane in hit.json().values() for i in lane["items"]}
        assert "CVE-2024-8888" in lane_ids  # the guard is meaningful: the CVE is on the board
        found = (await c.get("/api/cves?q=CVE-2024-8888")).json()
        assert [i["cve_id"] for i in found["items"]] == ["CVE-2024-8888"]
        assert (await c.get("/api/cves?q=Zyxwv")).json()["total"] == 0

        # signed in: the same reads still work, and the detail carries the victim story
        h, _ = bearer(db_session, mk_user(db_session))
        for path in ("/api/lanes", "/api/cves?q=CVE-2024-8888"):
            r = await c.get(path, headers=h)
            assert r.status_code == 200, path
            assert "x-cache" not in r.headers
        authed_lanes = (await c.get("/api/lanes", headers=h)).json()
        assert "CVE-2024-8888" in {
            i["cve_id"] for lane in authed_lanes.values() for i in lane["items"]
        }
        detail = await c.get("/api/cves/CVE-2024-8888", headers=h)
        assert _RL_MARK in detail.text


async def test_lane_filter_follows_windows(db_session):
    cve(db_session, "CVE-2024-7001", kev=True, kev_added=(NOW - timedelta(days=40)).date())
    r = await get(db_session, "/api/cves?lane=EXPLOITED")
    assert r.status_code == 200
    assert [i["cve_id"] for i in r.json()["items"]] == []
    r = await get(db_session, "/api/cves?kev=true")
    assert [i["cve_id"] for i in r.json()["items"]] == ["CVE-2024-7001"]


async def test_null_kev_added_out_of_lane_but_in_history(db_session):
    cve(db_session, "CVE-2024-7002", kev=True, kev_added=None)
    r = await get(db_session, "/api/cves?lane=EXPLOITED")
    assert [i["cve_id"] for i in r.json()["items"]] == []
    r = await get(db_session, "/api/lanes")
    assert r.json()["EXPLOITED"] == {"total": 0, "items": []}
    r = await get(db_session, "/api/cves?kev=true")
    assert [i["cve_id"] for i in r.json()["items"]] == ["CVE-2024-7002"]


async def test_lanes_total_and_limit(db_session):
    for i in range(7):
        cve(db_session, f"CVE-2024-{3000 + i}", kev=True, kev_added=NOW.date())
    body = (await get(db_session, "/api/lanes?limit=5")).json()
    assert len(body["EXPLOITED"]["items"]) == 5
    assert body["EXPLOITED"]["total"] == 7
    assert body["LIKELY"] == {"total": 0, "items": []}


async def test_lanes_invalid_range_422(db_session):
    assert (await get(db_session, "/api/lanes?range=90d")).status_code == 422


async def test_lanes_cache_key_varies_by_range(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=NOW.date())
    async with client(make_app(db_session)) as c:
        a = await c.get("/api/lanes?range=7d")
        b = await c.get("/api/lanes?range=24h")
        a2 = await c.get("/api/lanes?range=7d")
    assert a.headers["x-cache"] == "MISS"
    assert b.headers["x-cache"] == "MISS"
    assert a2.headers["x-cache"] == "HIT"


async def test_loud_stories_range(db_session):
    cve(db_session, "CVE-2024-0001")
    story(db_session, 1, ["CVE-2024-0001"], published=NOW - timedelta(days=5))
    story(db_session, 2, ["CVE-2024-0001"], published=NOW - timedelta(hours=1))
    assert len((await get(db_session, "/api/stories/loud?range=24h")).json()) == 1
    assert len((await get(db_session, "/api/stories/loud?range=7d")).json()) == 2
    assert (await get(db_session, "/api/stories/loud?range=90d")).status_code == 422


async def test_legacy_lane_excludes_restricted_only_cve_for_anon(db_session):
    cve(db_session, "CVE-2024-6666")
    s = story(db_session, 950, ["CVE-2024-6666"], title="Victim Two listed by grp")
    s.source = "ransomware.live"
    db_session.flush()
    anon = await get(db_session, "/api/cves?lane=LOUD&page_size=100")
    assert "CVE-2024-6666" not in {i["cve_id"] for i in anon.json()["items"]}
    h, _ = bearer(db_session, mk_user(db_session))
    authed = await get(db_session, "/api/cves?lane=LOUD&page_size=100", headers=h)
    assert "CVE-2024-6666" in {i["cve_id"] for i in authed.json()["items"]}
