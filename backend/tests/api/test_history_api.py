"""History/search API: CVE detail fields, KEV-date filter and sort, stories search, story lookup."""

from datetime import timedelta
from urllib.parse import quote

import fakeredis
import pytest
from test_read_api import (  # noqa: F401  (secrets_key is an autouse fixture)
    NOW,
    bearer,
    client,
    cve,
    get,
    make_app,
    mk_user,
    secrets_key,
    story,
)

from cvenom.models import Story, StoryCveLink


def ids(r):
    return [i["cve_id"] for i in r.json()["items"]]


async def test_detail_includes_new_fields(db_session):
    cve(db_session, "CVE-2024-0001")
    b = (await get(db_session, "/api/cves/CVE-2024-0001")).json()
    assert b["kev_name"] is None and b["kev_action"] is None and b["kev_notes"] is None
    assert b["kev_due"] is None and b["kev_ransomware"] is None
    assert b["cvss_vector"] is None and b["cvss_severity"] is None
    assert b["cwes"] == [] and b["references"] == [] and b["last_modified"] is None

    cve(
        db_session, "CVE-2024-0002", kev_name="N", kev_action="A", kev_notes="no",
        kev_due=NOW.date(), kev_ransomware=True, cvss_vector="CVSS:3.1/AV:N",
        cvss_severity="CRITICAL", cwes=["CWE-79"], last_modified=NOW,
        references=[{"url": "https://a.test", "tags": ["Patch"]}, {"url": 5}, "x", {"tags": []}],
    )
    b = (await get(db_session, "/api/cves/CVE-2024-0002")).json()
    assert b["kev_name"] == "N" and b["kev_due"] == NOW.date().isoformat()
    assert b["kev_ransomware"] is True and b["cwes"] == ["CWE-79"]
    assert b["references"] == [{"url": "https://a.test", "tags": ["Patch"]}]
    assert b["last_modified"].endswith("Z") or "+00:00" in b["last_modified"]
    # the lean item shape is unchanged
    items = (await get(db_session, "/api/cves")).json()["items"]
    assert "references" not in items[0] and "kev_name" not in items[0]


async def test_kev_date_range_filter(db_session):
    d = NOW.date()
    for n, off in [(1, 10), (2, 5), (3, 1)]:
        cve(db_session, f"CVE-2024-000{n}", kev=True, kev_added=d - timedelta(days=off))
    cve(db_session, "CVE-2024-0004")
    r = await get(
        db_session, f"/api/cves?kev_from={d - timedelta(days=5)}&kev_to={d - timedelta(days=1)}"
    )
    assert sorted(ids(r)) == ["CVE-2024-0002", "CVE-2024-0003"]  # kev_to inclusive
    r = await get(db_session, f"/api/cves?kev_to={d - timedelta(days=10)}")
    assert ids(r) == ["CVE-2024-0001"]
    r = await get(db_session, f"/api/cves?kev_from={d - timedelta(days=1)}")
    assert ids(r) == ["CVE-2024-0003"]


async def test_sort_default_kev_added_when_kev_only(db_session):
    d = NOW.date()
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=d - timedelta(days=3),
        published=NOW - timedelta(days=1))
    cve(db_session, "CVE-2024-0002", kev=True, kev_added=d, published=NOW - timedelta(days=9))
    cve(db_session, "CVE-2024-0003", kev=True, published=NOW - timedelta(days=2))  # NULL kev_added
    assert ids(await get(db_session, "/api/cves?kev=true")) == [
        "CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0003"]
    # without kev=true the default stays published desc
    assert ids(await get(db_session, "/api/cves")) == [
        "CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]
    assert ids(await get(db_session, "/api/cves?sort=published&kev=true")) == [
        "CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]


async def test_sort_cvss_and_invalid_sort_422(db_session):
    cve(db_session, "CVE-2024-0001", cvss=5.0, published=NOW - timedelta(days=1))
    cve(db_session, "CVE-2024-0002", cvss=9.0, published=NOW - timedelta(days=3))
    cve(db_session, "CVE-2024-0003", cvss=9.0, published=NOW - timedelta(days=2))
    cve(db_session, "CVE-2024-0004")  # cvss NULL last
    assert ids(await get(db_session, "/api/cves?sort=cvss")) == [
        "CVE-2024-0003", "CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0004"]
    assert (await get(db_session, "/api/cves?sort=bogus")).status_code == 422


async def test_lane_keeps_default_order_unless_sort_given(db_session):
    d = NOW.date()
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=d, published=NOW - timedelta(days=5))
    cve(db_session, "CVE-2024-0002", kev=True, kev_added=d, published=NOW - timedelta(days=1))
    # lane= without sort keeps the published-desc order even with kev=true
    assert ids(await get(db_session, "/api/cves?lane=EXPLOITED&kev=true")) == [
        "CVE-2024-0002", "CVE-2024-0001"]
    # an explicit sort applies
    assert ids(await get(db_session, "/api/cves?lane=EXPLOITED&kev=true&sort=kev_added")) == [
        "CVE-2024-0001", "CVE-2024-0002"]


def sstory(db, n, title="t", summary="x", source="src", published=None, cve_ids=()):
    s = story(db, n, cve_ids, published=published, title=title)
    s.summary = summary
    s.source = source
    db.flush()
    return s


async def test_stories_q_matches_title_and_summary_with_like_escaping(db_session):
    sstory(db_session, 1, title="Alpha exploit")
    sstory(db_session, 2, summary="the ALPHA thing")
    sstory(db_session, 3, title="100% sure")
    sstory(db_session, 4, title="a_b")
    sstory(db_session, 5, title="axb")
    sstory(db_session, 6, title="back\\slash")
    sstory(db_session, 7, title="100 sure")

    async def q(term):
        r = await get(db_session, f"/api/stories?q={quote(term, safe='')}")
        assert r.status_code == 200
        return {i["url"] for i in r.json()["items"]}

    assert await q("alpha") == {"https://ex.test/1", "https://ex.test/2"}
    assert await q("%") == {"https://ex.test/3"}
    assert await q("_") == {"https://ex.test/4"}
    assert await q("\\") == {"https://ex.test/6"}


async def test_stories_nul_is_422(db_session):
    assert (await get(db_session, "/api/stories?q=a%00b")).status_code == 422
    assert (await get(db_session, "/api/stories?source=a%00b")).status_code == 422
    assert (await get(db_session, "/api/story?url=a%00b")).status_code == 422


async def test_stories_newest_first_and_total(db_session):
    for i in range(5):
        sstory(db_session, i, published=NOW - timedelta(hours=i + 1))
    cve(db_session, "CVE-2024-0001")
    s0 = db_session.query(Story).filter_by(url="https://ex.test/0").one()
    db_session.add(StoryCveLink(story_id=s0.id, cve_id="CVE-2024-0001"))
    sstory(db_session, 9, source="other", published=NOW - timedelta(hours=20))
    db_session.flush()
    b = (await get(db_session, "/api/stories?page_size=3")).json()
    assert b["total"] == 6 and b["page"] == 1 and b["page_size"] == 3
    assert [i["url"][-1] for i in b["items"]] == ["0", "1", "2"]
    assert b["items"][0]["cve_ids"] == ["CVE-2024-0001"]
    assert set(b["items"][0]) == {"title", "summary", "url", "source", "published", "cve_ids"}
    b2 = (await get(db_session, "/api/stories?page_size=3&page=2")).json()
    assert [i["url"][-1] for i in b2["items"]] == ["3", "4", "9"]
    assert (await get(db_session, "/api/stories?source=other")).json()["total"] == 1
    assert (await get(db_session, "/api/stories?source=oth")).json()["total"] == 0  # exact
    for bad in ("page=0", "page=10001", "page_size=0", "page_size=101", "q=" + "a" * 201,
                "source=" + "a" * 65):
        assert (await get(db_session, f"/api/stories?{bad}")).status_code == 422


async def test_stories_anon_restricted_filtered_before_limit(db_session):
    sstory(db_session, 1000, title="news", published=NOW - timedelta(days=3))
    for i in range(30):
        sstory(db_session, i, source="ransomware.live", published=NOW - timedelta(minutes=i + 1))
    anon = (await get(db_session, "/api/stories?page_size=25")).json()
    assert anon["total"] == 1 and [i["source"] for i in anon["items"]] == ["src"]
    h, _ = bearer(db_session, mk_user(db_session))
    authed = (await get(db_session, "/api/stories?page_size=25", headers=h)).json()
    assert authed["total"] == 31 and len(authed["items"]) == 25
    r = (await get(db_session, "/api/stories?source=ransomware.live")).json()
    assert r["total"] == 0 and r["items"] == []


async def test_stories_anon_cached_without_q_bypassed_with_q(db_session):
    sstory(db_session, 1)
    app = make_app(db_session, redis=fakeredis.FakeAsyncRedis())
    async with client(app) as c:
        r1 = await c.get("/api/stories?page=1")
        r2 = await c.get("/api/stories?page=1")
        assert r1.headers["x-cache"] == "MISS" and r2.headers["x-cache"] == "HIT"
        assert "x-cache" not in (await c.get("/api/stories?q=t")).headers
        l1 = await c.get("/api/stories/loud")
        l2 = await c.get("/api/stories/loud")
        assert l1.headers["x-cache"] == "MISS" and l2.headers["x-cache"] == "HIT"
        assert isinstance(l2.json(), list)  # not shadowed by the /api/stories entry
        assert "x-cache" not in (await c.get("/api/story?url=https://ex.test/1")).headers


async def test_story_detail_found_with_details_for_authed(db_session):
    cve(db_session, "CVE-2024-0001")
    s = sstory(db_session, 1, source="ransomware.live", cve_ids=["CVE-2024-0001"])
    s.details = {"group": "grp"}
    db_session.flush()
    h, _ = bearer(db_session, mk_user(db_session))
    r = await get(db_session, "/api/story?url=https://ex.test/1", headers=h)
    assert r.status_code == 200
    b = r.json()
    assert b["details"] == {"group": "grp"} and b["cve_ids"] == ["CVE-2024-0001"]
    assert set(b) == {"title", "summary", "url", "source", "published", "cve_ids", "details"}
    sstory(db_session, 2)
    assert (await get(db_session, "/api/story?url=https://ex.test/2")).json()["details"] == {}


async def test_story_detail_restricted_anon_404_identical_to_missing(db_session):
    sstory(db_session, 1, source="ransomware.live")
    a = await get(db_session, "/api/story?url=https://ex.test/1")
    b = await get(db_session, "/api/story?url=https://ex.test/nope")
    assert a.status_code == b.status_code == 404
    assert a.content == b.content == b'{"error":"not_found"}'
    assert dict(a.headers) == dict(b.headers)


async def test_story_url_too_long_422(db_session):
    assert (await get(db_session, "/api/story?url=" + "a" * 2049)).status_code == 422
    assert (await get(db_session, "/api/story")).status_code == 422


async def test_page_past_end_returns_empty_items_with_true_total(db_session):
    for n in (1, 2, 3):
        cve(db_session, f"CVE-2024-000{n}")
        sstory(db_session, n)
    r = (await get(db_session, "/api/cves?page=9999")).json()
    assert r["items"] == [] and r["total"] == 3
    r = (await get(db_session, "/api/stories?page=9999")).json()
    assert r["items"] == [] and r["total"] == 3
