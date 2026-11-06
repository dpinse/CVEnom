"""Threats search: GET /api/cves added/status/sev/poc/nopatch/due/sort/q + GET /api/stories added."""

from datetime import timedelta

import pytest
from test_read_api import (  # noqa: F401  (secrets_key is an autouse fixture)
    NOW,
    bearer,
    cve,
    geo,
    get,
    mk_user,
    secrets_key,
    story,
)

from cvenom.api.routes_read import CACHE_PATHS
from cvenom.models import Cve, CveEvent, Story
from cvenom.readmodels import product_label

TODAY = NOW.date()
OLD = NOW - timedelta(days=400)


def ids(r):
    assert r.status_code == 200, r.text
    return [i["cve_id"] for i in r.json()["items"]]


def poc_event(db, cve_id, days_ago):
    db.add(
        CveEvent(
            cve_id=cve_id, kind="poc_published", source="exploitdb",
            occurred_at=NOW - timedelta(days=days_ago),
        )
    )
    db.flush()


# ---------------------------------------------------------------- added window


@pytest.mark.parametrize(
    "added,days",
    [("day", 1), ("week", 7), ("14d", 14), ("month", 30), ("90d", 90), ("year", 365)],
)
async def test_added_window_uses_published(db_session, added, days):
    cve(db_session, "CVE-2024-0001", published=NOW - timedelta(days=days) + timedelta(hours=2))
    cve(db_session, "CVE-2024-0002", published=NOW - timedelta(days=days) - timedelta(hours=2))
    assert ids(await get(db_session, f"/api/cves?added={added}")) == ["CVE-2024-0001"]


async def test_added_any_is_default_and_invalid_is_422(db_session):
    cve(db_session, "CVE-2024-0001", published=OLD)
    assert ids(await get(db_session, "/api/cves")) == ["CVE-2024-0001"]
    assert ids(await get(db_session, "/api/cves?added=any")) == ["CVE-2024-0001"]
    assert (await get(db_session, "/api/cves?added=decade")).status_code == 422


async def test_added_is_kev_date_when_exploited(db_session):
    cve(db_session, "CVE-2024-0001", published=OLD, kev=True, kev_added=TODAY - timedelta(days=2))
    cve(db_session, "CVE-2024-0002", published=NOW, kev=True, kev_added=TODAY - timedelta(days=20))
    r = await get(db_session, "/api/cves?status=exploited&added=week")
    assert ids(r) == ["CVE-2024-0001"]
    # Without the Exploited status "added" is the published date.
    assert ids(await get(db_session, "/api/cves?added=week")) == ["CVE-2024-0002"]


# ---------------------------------------------------------------- status


async def test_status_filters(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=TODAY, epss_percentile=0.99, cvss=9.8)
    cve(db_session, "CVE-2024-0002", epss_percentile=0.99, cvss=5.0)
    cve(db_session, "CVE-2024-0003", epss_percentile=0.10, cvss=9.0)
    cve(db_session, "CVE-2024-0004", epss_percentile=0.10, cvss=3.0)
    story(db_session, 1, ["CVE-2024-0004"])
    got = {
        s: set(ids(await get(db_session, f"/api/cves?status={s}")))
        for s in ("all", "exploited", "likely", "news", "critical")
    }
    assert got["all"] == {f"CVE-2024-000{i}" for i in (1, 2, 3, 4)}
    assert got["exploited"] == {"CVE-2024-0001"}
    assert got["likely"] == {"CVE-2024-0002"}  # KEV is excluded from "likely next"
    assert got["news"] == {"CVE-2024-0004"}
    assert got["critical"] == {"CVE-2024-0001", "CVE-2024-0003"}
    assert (await get(db_session, "/api/cves?status=nope")).status_code == 422


async def test_exclude_kev(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=TODAY, cvss=9.8)
    cve(db_session, "CVE-2024-0002", cvss=9.8)
    assert ids(await get(db_session, "/api/cves?status=critical&exclude_kev=1")) == [
        "CVE-2024-0002"
    ]


async def test_news_status_respects_added_window_on_story_date(db_session):
    cve(db_session, "CVE-2024-0001", published=OLD)
    cve(db_session, "CVE-2024-0002", published=OLD)
    story(db_session, 1, ["CVE-2024-0001"], published=NOW - timedelta(hours=3))
    story(db_session, 2, ["CVE-2024-0002"], published=NOW - timedelta(days=3))
    assert ids(await get(db_session, "/api/cves?status=news&added=day")) == ["CVE-2024-0001"]
    assert set(ids(await get(db_session, "/api/cves?status=news&added=week"))) == {
        "CVE-2024-0001", "CVE-2024-0002",
    }
    assert set(ids(await get(db_session, "/api/cves?status=news"))) == {
        "CVE-2024-0001", "CVE-2024-0002",
    }


# ---------------------------------------------------------------- sev / poc / nopatch


async def test_sev_bands_and_validation(db_session):
    for cid, score in [
        ("CVE-2024-0001", 9.0), ("CVE-2024-0002", 8.9), ("CVE-2024-0003", 7.0),
        ("CVE-2024-0004", 6.9), ("CVE-2024-0005", 4.0), ("CVE-2024-0006", 3.9),
        ("CVE-2024-0007", 0.1), ("CVE-2024-0008", None),
    ]:
        cve(db_session, cid, cvss=score)

    async def sev(v):
        return set(ids(await get(db_session, f"/api/cves?sev={v}")))

    assert await sev("crit") == {"CVE-2024-0001"}
    assert await sev("high") == {"CVE-2024-0002", "CVE-2024-0003"}
    assert await sev("med") == {"CVE-2024-0004", "CVE-2024-0005"}
    assert await sev("low") == {"CVE-2024-0006", "CVE-2024-0007"}
    assert await sev("crit,high") == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
    assert len(await sev("low,med,high,crit")) == 7  # unscored matches no band
    assert len(ids(await get(db_session, "/api/cves"))) == 8  # none selected = any
    assert (await get(db_session, "/api/cves?sev=critical")).status_code == 422
    assert (await get(db_session, "/api/cves?sev=crit,bogus")).status_code == 422


async def test_poc_and_nopatch(db_session):
    cve(db_session, "CVE-2024-0001", poc_badge=True, patch_available=False)
    cve(db_session, "CVE-2024-0002", poc_badge=False, patch_available=True)
    cve(db_session, "CVE-2024-0003", poc_badge=True, patch_available=None)
    assert set(ids(await get(db_session, "/api/cves?poc=1"))) == {"CVE-2024-0001", "CVE-2024-0003"}
    assert ids(await get(db_session, "/api/cves?nopatch=1")) == ["CVE-2024-0001"]
    assert ids(await get(db_session, "/api/cves?poc=1&nopatch=1")) == ["CVE-2024-0001"]


async def test_poc_with_added_means_event_in_window(db_session):
    cve(db_session, "CVE-2024-0001", published=OLD, poc_badge=True)
    cve(db_session, "CVE-2024-0002", published=OLD, poc_badge=True)
    cve(db_session, "CVE-2024-0003", published=NOW, poc_badge=False)  # no poc event
    poc_event(db_session, "CVE-2024-0001", 2)
    poc_event(db_session, "CVE-2024-0002", 20)
    assert ids(await get(db_session, "/api/cves?poc=1&added=week")) == ["CVE-2024-0001"]
    assert set(ids(await get(db_session, "/api/cves?poc=1&added=month"))) == {
        "CVE-2024-0001", "CVE-2024-0002",
    }


# ---------------------------------------------------------------- due


async def test_due_7d_window_and_sort(db_session):
    for cid, delta in [
        ("CVE-2024-0001", 7), ("CVE-2024-0002", 8), ("CVE-2024-0003", -1),
        ("CVE-2024-0004", 0), ("CVE-2024-0005", 3),
    ]:
        cve(db_session, cid, kev=True, kev_added=TODAY - timedelta(days=90),
            kev_due=TODAY + timedelta(days=delta))
    cve(db_session, "CVE-2024-0006", kev=False, kev_due=TODAY + timedelta(days=1))
    r = await get(db_session, "/api/cves?due=7d")
    assert ids(r) == ["CVE-2024-0004", "CVE-2024-0005", "CVE-2024-0001"]  # soonest first
    assert (await get(db_session, "/api/cves?due=30d")).status_code == 422


async def test_sort_due_is_kev_only_soonest_first(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_due=TODAY + timedelta(days=30))
    cve(db_session, "CVE-2024-0002", kev=True, kev_due=TODAY - timedelta(days=30))
    cve(db_session, "CVE-2024-0003", kev=True, kev_due=None)
    cve(db_session, "CVE-2024-0004", kev=False, kev_due=TODAY)
    assert ids(await get(db_session, "/api/cves?sort=due")) == ["CVE-2024-0002", "CVE-2024-0001"]


# ---------------------------------------------------------------- sorts


async def test_sort_newest_default_and_exploited_uses_kev_added(db_session):
    cve(db_session, "CVE-2024-0001", published=NOW - timedelta(days=1), kev=True,
        kev_added=TODAY - timedelta(days=10))
    cve(db_session, "CVE-2024-0002", published=NOW - timedelta(days=50), kev=True,
        kev_added=TODAY - timedelta(days=1))
    assert ids(await get(db_session, "/api/cves")) == ["CVE-2024-0001", "CVE-2024-0002"]
    assert ids(await get(db_session, "/api/cves?sort=newest")) == ["CVE-2024-0001", "CVE-2024-0002"]
    r = await get(db_session, "/api/cves?status=exploited")
    assert ids(r) == ["CVE-2024-0002", "CVE-2024-0001"]


async def test_sort_hot_follows_heat_rank(db_session):
    cve(db_session, "CVE-2024-0001", published=OLD, kev=True, cvss=5.0, kev_added=TODAY)
    cve(db_session, "CVE-2024-0002", published=OLD, epss_percentile=0.99, cvss=9.8)
    cve(db_session, "CVE-2024-0003", published=OLD, epss_percentile=0.50, cvss=9.8)
    cve(db_session, "CVE-2024-0004", published=NOW, cvss=2.0)
    cve(db_session, "CVE-2024-0005", published=OLD, cvss=None)
    assert ids(await get(db_session, "/api/cves?sort=hot")) == [
        "CVE-2024-0001",  # KEV gate
        "CVE-2024-0002",
        "CVE-2024-0003",
        "CVE-2024-0004",  # recency + low cvss still beats unscored
        "CVE-2024-0005",
    ]


async def test_sort_hot_matches_python_heat_rank(db_session):
    """The SQL port orders rows exactly like scoring.heat_rank."""
    from cvenom.config import get_settings
    from cvenom.scoring import CveView, heat_rank

    specs = [
        ("CVE-2024-0001", dict(kev=True, cvss=5.0, kev_added=TODAY, published=OLD)),
        ("CVE-2024-0002", dict(epss_percentile=0.9, cvss=9.0, published=NOW - timedelta(hours=5))),
        ("CVE-2024-0003", dict(epss_percentile=0.9, cvss=9.0, published=NOW - timedelta(hours=40))),
        ("CVE-2024-0004", dict(epss_percentile=0.9, cvss=9.0, published=OLD, patch_available=False)),
        ("CVE-2024-0005", dict(cvss=1.0, published=OLD)),
    ]
    for cid, kw in specs:
        cve(db_session, cid, **kw)
    cfg = get_settings()
    views = [
        CveView(cve_id=cid, published=kw["published"], cvss=kw.get("cvss"),
                epss_percentile=kw.get("epss_percentile"), kev=kw.get("kev", False),
                patch_available=kw.get("patch_available"))
        for cid, kw in specs
    ]
    expected = [v.cve_id for v in sorted(views, key=lambda v: (-heat_rank(v, NOW, cfg), v.cve_id))]
    assert ids(await get(db_session, "/api/cves?sort=hot")) == expected


async def test_sort_trending_stories_then_epss_then_newest(db_session):
    for i, kw in enumerate(
        [
            dict(epss_percentile=0.1, published=NOW - timedelta(days=3)),   # 1: 2 stories
            dict(epss_percentile=0.9, published=NOW - timedelta(days=9)),   # 2: 1 story
            dict(epss_percentile=0.5, published=NOW - timedelta(days=9)),   # 3: 1 story
            dict(epss_percentile=None, published=NOW - timedelta(days=1)),  # 4: 0, newest
            dict(epss_percentile=None, published=NOW - timedelta(days=5)),  # 5: 0, older
            dict(epss_percentile=0.1, published=NOW - timedelta(days=9)),   # 6: old story only
        ],
        start=1,
    ):
        cve(db_session, f"CVE-2024-000{i}", **kw)
    story(db_session, 1, ["CVE-2024-0001"], published=NOW - timedelta(days=1))
    story(db_session, 2, ["CVE-2024-0001"], published=NOW - timedelta(days=2))
    story(db_session, 3, ["CVE-2024-0002"], published=NOW - timedelta(days=3))
    story(db_session, 4, ["CVE-2024-0003"], published=NOW - timedelta(days=4))
    story(db_session, 5, ["CVE-2024-0006"] * 1, published=NOW - timedelta(days=30))
    r = await get(db_session, "/api/cves?sort=trending")
    assert ids(r)[:3] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    # 0-story rows: epss desc nulls last -> 0006 (0.1) first, then newest published
    assert ids(r)[3:] == ["CVE-2024-0006", "CVE-2024-0004", "CVE-2024-0005"]


async def test_legacy_sorts_still_accepted(db_session):
    cve(db_session, "CVE-2024-0001", cvss=3.0, published=NOW - timedelta(days=2))
    cve(db_session, "CVE-2024-0002", cvss=9.0, published=NOW - timedelta(days=3))
    assert ids(await get(db_session, "/api/cves?sort=cvss")) == ["CVE-2024-0002", "CVE-2024-0001"]
    assert ids(await get(db_session, "/api/cves?sort=published")) == [
        "CVE-2024-0001", "CVE-2024-0002",
    ]
    assert (await get(db_session, "/api/cves?sort=bogus")).status_code == 422


# ---------------------------------------------------------------- q / exact id


async def test_q_matches_vendor_product_and_kev_name(db_session):
    cve(db_session, "CVE-2024-0001", affected=["Ivanti Connect Secure"], summary="x")
    cve(db_session, "CVE-2024-0002", kev=True, kev_name="Fortinet FortiOS bug", summary="x")
    cve(db_session, "CVE-2024-0003", summary="unrelated")
    assert ids(await get(db_session, "/api/cves?q=ivanti")) == ["CVE-2024-0001"]
    assert ids(await get(db_session, "/api/cves?q=fortios")) == ["CVE-2024-0002"]
    assert ids(await get(db_session, "/api/cves?q=%25")) == []  # wildcard is escaped


async def test_exact_cve_id_ignores_all_filters_and_flags_it(db_session):
    cve(db_session, "CVE-2024-0001", published=OLD, cvss=2.0, kev=True,
        kev_added=TODAY - timedelta(days=9))
    cve(db_session, "CVE-2024-0002", published=NOW, cvss=9.9)
    r = await get(db_session, "/api/cves?q=cve-2024-0001&added=day&status=critical&sev=crit&poc=1")
    body = r.json()
    assert [i["cve_id"] for i in body["items"]] == ["CVE-2024-0001"] and body["total"] == 1
    assert body["exact_match"] is True and body["exact_match_filtered_out"] is True
    # An exact id that the filters also match is not flagged as filtered out.
    ok = (await get(db_session, "/api/cves?q=CVE-2024-0002&added=day")).json()
    assert ok["exact_match"] is True and ok["exact_match_filtered_out"] is False
    # Not an exact id: ordinary filtered search, no flag.
    plain = (await get(db_session, "/api/cves?q=CVE-2024-000")).json()
    assert plain["exact_match"] is False and plain["total"] == 2
    # Unknown exact id: empty, flagged exact, not "filtered out".
    gone = (await get(db_session, "/api/cves?q=CVE-2030-9999&added=day")).json()
    assert gone["total"] == 0 and gone["exact_match"] is True
    assert gone["exact_match_filtered_out"] is False


# ---------------------------------------------------------------- product / last_seen


def test_product_label_precedence():
    def c(**kw):
        return Cve(cve_id="CVE-2024-0001", **kw)

    # 1. first `affected` entry without ":" beats everything
    assert product_label(
        c(affected=["a:b", "Vendor Product"], affected_versions=[{"product": "p", "source": "OSV"}])
    ) == "Vendor Product"
    # 2. affected_versions: NVD "vendor product", OSV bare product
    assert product_label(
        c(affected=["x:y"], affected_versions=[{"vendor": "acme", "product": "w", "source": "NVD"}])
    ) == "acme w"
    assert product_label(
        c(affected=[], affected_versions=[{"product": "pkg", "ecosystem": "npm", "source": "OSV"}])
    ) == "pkg"
    # 3. part after ":" of the first affected entry
    assert product_label(c(affected=["cpe:widget"], affected_versions=[])) == "widget"
    # 4. nothing
    assert product_label(c(affected=[], affected_versions=[])) is None
    assert product_label(c(affected=[5, None], affected_versions=["junk"])) is None


async def test_items_have_product_and_last_seen(db_session):
    cve(db_session, "CVE-2024-0001", published=NOW - timedelta(days=30), kev=True,
        kev_added=TODAY - timedelta(days=3), affected=["Ivanti Connect Secure"])
    cve(db_session, "CVE-2024-0002", published=NOW - timedelta(days=30))
    cve(db_session, "CVE-2024-0003", published=None)
    story(db_session, 1, ["CVE-2024-0002"], published=NOW - timedelta(hours=1))
    items = {i["cve_id"]: i for i in (await get(db_session, "/api/cves?page_size=10")).json()["items"]}
    assert items["CVE-2024-0001"]["product"] == "Ivanti Connect Secure"
    assert items["CVE-2024-0002"]["product"] is None
    # kev_added at 00:00 UTC beats the older published date
    assert items["CVE-2024-0001"]["last_seen"].startswith((TODAY - timedelta(days=3)).isoformat())
    # a fresh story beats published
    assert items["CVE-2024-0002"]["last_seen"][:13] == (NOW - timedelta(hours=1)).isoformat()[:13]
    assert items["CVE-2024-0003"]["last_seen"] is None
    # lanes and detail carry them too
    d = (await get(db_session, "/api/cves/CVE-2024-0001")).json()
    assert d["product"] == "Ivanti Connect Secure" and d["last_seen"] is not None


async def test_anon_last_seen_and_news_exclude_ransomware_stories(db_session):
    cve(db_session, "CVE-2024-0001", published=OLD)
    cve(db_session, "CVE-2024-0002", published=OLD)
    rl = story(db_session, 1, ["CVE-2024-0001"], published=NOW - timedelta(hours=1))
    rl.source = "ransomware.live"
    story(db_session, 2, ["CVE-2024-0002"], published=NOW - timedelta(days=2))
    db_session.flush()

    anon = await get(db_session, "/api/cves?status=news")
    assert ids(anon) == ["CVE-2024-0002"]
    seen = {i["cve_id"]: i["last_seen"] for i in (await get(db_session, "/api/cves")).json()["items"]}
    assert seen["CVE-2024-0001"].startswith(OLD.date().isoformat())  # restricted story ignored
    assert "ransomware" not in (await get(db_session, "/api/cves?sort=trending")).text

    h, _ = bearer(db_session, mk_user(db_session))
    authed = await get(db_session, "/api/cves?status=news", headers=h)
    assert set(ids(authed)) == {"CVE-2024-0001", "CVE-2024-0002"}
    own = {
        i["cve_id"]: i["last_seen"]
        for i in (await get(db_session, "/api/cves", headers=h)).json()["items"]
    }
    assert own["CVE-2024-0001"][:13] == (NOW - timedelta(hours=1)).isoformat()[:13]


async def test_anon_trending_ignores_restricted_story_counts(db_session):
    cve(db_session, "CVE-2024-0001", published=NOW - timedelta(days=9))
    cve(db_session, "CVE-2024-0002", published=NOW - timedelta(days=8))
    for n in range(3):
        s = story(db_session, n, ["CVE-2024-0001"], published=NOW - timedelta(hours=n + 1))
        s.source = "ransomware.live"
    story(db_session, 10, ["CVE-2024-0002"], published=NOW - timedelta(hours=1))
    db_session.flush()
    assert ids(await get(db_session, "/api/cves?sort=trending")) == ["CVE-2024-0002", "CVE-2024-0001"]
    h, _ = bearer(db_session, mk_user(db_session))
    assert ids(await get(db_session, "/api/cves?sort=trending", headers=h)) == [
        "CVE-2024-0001", "CVE-2024-0002",
    ]


# ---------------------------------------------------------------- back-compat


async def test_old_params_still_work(db_session):
    cve(db_session, "CVE-2024-0001", kev=True, kev_added=TODAY, kev_source="cisa", cvss=9.0,
        published=NOW - timedelta(days=3))
    cve(db_session, "CVE-2024-0002", kev=False, cvss=4.0, published=NOW - timedelta(days=40))
    cve(db_session, "CVE-2024-0003", kev=True, kev_added=TODAY - timedelta(days=50),
        kev_source="vulncheck", cvss=9.9, published=NOW - timedelta(days=60))
    assert ids(await get(db_session, "/api/cves?kev=true")) == ["CVE-2024-0001", "CVE-2024-0003"]
    assert ids(await get(db_session, "/api/cves?kev=false")) == ["CVE-2024-0002"]
    assert ids(await get(db_session, "/api/cves?min_cvss=9.5")) == ["CVE-2024-0003"]
    assert ids(await get(db_session, "/api/cves?source=vulncheck")) == ["CVE-2024-0003"]
    frm = (NOW - timedelta(days=45)).date().isoformat()
    assert ids(await get(db_session, f"/api/cves?from={frm}")) == ["CVE-2024-0001", "CVE-2024-0002"]
    to = (NOW - timedelta(days=45)).date().isoformat()
    assert ids(await get(db_session, f"/api/cves?to={to}")) == ["CVE-2024-0003"]
    kf = (TODAY - timedelta(days=5)).isoformat()
    assert ids(await get(db_session, f"/api/cves?kev_from={kf}")) == ["CVE-2024-0001"]
    assert ids(await get(db_session, f"/api/cves?kev_to={kf}")) == ["CVE-2024-0003"]
    assert ids(await get(db_session, "/api/cves?lane=EXPLOITED")) == ["CVE-2024-0001"]


# ---------------------------------------------------------------- summary-count equality


RANGES = [("24h", "day"), ("7d", "week"), ("14d", "14d"), ("30d", "month")]


def _equality_dataset(db):
    old = NOW - timedelta(days=200)
    # KEV listings at assorted ages (some with due dates around the window edge)
    for i, age in enumerate([0, 1, 3, 7, 10, 14, 20, 30, 45, 120]):
        cve(db, f"CVE-2026-1{i:03d}", published=old, kev=True, kev_added=TODAY - timedelta(days=age),
            kev_due=TODAY + timedelta(days=i - 2), cvss=9.5 if i % 2 else 5.0)
    # non-KEV criticals published at assorted ages; plus near-misses
    for i, hours in enumerate([2, 20, 30, 24 * 6, 24 * 9, 24 * 13, 24 * 20, 24 * 29, 24 * 40, 24 * 90]):
        cve(db, f"CVE-2026-2{i:03d}", published=NOW - timedelta(hours=hours), cvss=9.1)
    cve(db, "CVE-2026-2900", published=NOW - timedelta(hours=3), cvss=8.9)  # not critical
    cve(db, "CVE-2026-2901", published=NOW - timedelta(hours=3), cvss=9.9, kev=True,
        kev_added=TODAY - timedelta(days=400))  # KEV: excluded from "fresh"
    # PoC events at assorted ages (two sources on one CVE count once)
    for i, age in enumerate([0, 2, 6, 9, 13, 25, 60]):
        cid = f"CVE-2026-3{i:03d}"
        cve(db, cid, published=old, poc_badge=True)
        poc_event(db, cid, age)
    db.add(CveEvent(cve_id="CVE-2026-3001", kind="poc_published", source="github",
                    occurred_at=NOW - timedelta(days=1)))
    db.flush()


@pytest.mark.parametrize("rng,added", RANGES)
async def test_dashboard_links_match_summary_counts(db_session, rng, added):
    _equality_dataset(db_session)
    summary = (await get(db_session, f"/api/summary?range={rng}")).json()

    async def total(qs):
        r = await get(db_session, f"/api/cves?{qs}&page_size=1")
        assert r.status_code == 200, r.text
        return r.json()["total"]

    assert summary["new_kev"] > 0 and summary["new_critical"] > 0 and summary["public_exploits"] > 0
    assert await total(f"status=exploited&added={added}") == summary["new_kev"]
    assert await total(f"status=critical&exclude_kev=1&added={added}") == summary["new_critical"]
    assert await total(f"poc=1&added={added}") == summary["public_exploits"]
    assert await total("due=7d") == summary["kev_due_soon"] > 0


async def test_dashboard_counts_differ_across_ranges(db_session):
    """Guards the equality test against a dataset where every range is identical."""
    _equality_dataset(db_session)
    news = [
        (await get(db_session, f"/api/summary?range={r}")).json()["new_kev"] for r, _ in RANGES
    ]
    assert news == sorted(set(news)) and len(set(news)) == 4


# ---------------------------------------------------------------- stories added + cache


async def test_stories_added_window(db_session):
    for n, ago in [(1, timedelta(hours=3)), (2, timedelta(days=3)), (3, timedelta(days=60))]:
        db_session.add(Story(url=f"https://ex.test/{n}", content_hash=f"h{n}", source="src",
                             title=f"t{n}", summary="", published=NOW - ago))
    db_session.flush()

    async def titles(qs):
        r = await get(db_session, f"/api/stories?{qs}")
        assert r.status_code == 200
        return {i["title"] for i in r.json()["items"]}

    assert await titles("added=day") == {"t1"}
    assert await titles("added=week") == {"t1", "t2"}
    assert await titles("added=year") == {"t1", "t2", "t3"}
    assert await titles("added=any") == {"t1", "t2", "t3"}
    assert (await get(db_session, "/api/stories?added=bogus")).status_code == 422


async def test_stories_added_anon_never_lists_ransomware(db_session):
    s = story(db_session, 1, [], published=NOW - timedelta(hours=1))
    s.source = "ransomware.live"
    db_session.flush()
    r = await get(db_session, "/api/stories?added=week")
    assert r.json()["total"] == 0


def test_cache_paths_allow_added_but_never_free_text():
    assert "added" in CACHE_PATHS["/api/stories"]
    assert "q" not in CACHE_PATHS["/api/stories"]
    assert "/api/cves" not in CACHE_PATHS  # free-text search is never cached


async def test_anon_search_never_carries_ransomware_victims(db_session):
    cve(db_session, "CVE-2024-0001", published=NOW - timedelta(days=1))
    s = story(db_session, 1, ["CVE-2024-0001"], title="Victim Inc listed by grp")
    s.source = "ransomware.live"
    db_session.flush()
    for qs in ("added=week", "status=news&added=week", "sort=trending", "sort=hot", "q=victim"):
        r = await get(db_session, f"/api/cves?{qs}")
        assert r.status_code == 200 and "Victim Inc" not in r.text and "ransomware" not in r.text
    assert ids(await get(db_session, "/api/cves?status=news")) == []


async def test_threats_query_count_is_flat(db_session):
    from sqlalchemy import event

    for i in range(20):
        cve(db_session, f"CVE-2025-{i:04d}", published=NOW - timedelta(hours=i), cvss=9.5)
        story(db_session, i, [f"CVE-2025-{i:04d}"])
    engine = db_session.get_bind().engine
    selects: list[str] = []

    def count(conn, cursor, statement, *a):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    event.listen(engine, "before_cursor_execute", count)
    try:
        r = await get(db_session, "/api/cves?sort=hot&status=critical&page_size=20")
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert len(r.json()["items"]) == 20
    assert len(selects) <= 6


# ---------------------------------------------------------------- GET /api/cves/{id}


def ev(db, cve_id, kind, source, hours_ago, **detail):
    db.add(CveEvent(cve_id=cve_id, kind=kind, source=source, detail=detail,
                    occurred_at=NOW - timedelta(hours=hours_ago)))
    db.flush()


async def test_detail_events_sorted_and_restricted(db_session):
    cve(db_session, "CVE-2024-0001")
    ev(db_session, "CVE-2024-0001", "published", "nvd", 50)
    ev(db_session, "CVE-2024-0001", "first_news", "ransomware.live", 40)
    ev(db_session, "CVE-2024-0001", "kev_added", "cisa", 10)
    ev(db_session, "CVE-2024-0001", "first_news", "bleeping", 30)
    anon = (await get(db_session, "/api/cves/CVE-2024-0001")).json()["events"]
    assert [(e["kind"], e["source"]) for e in anon] == [
        ("published", "nvd"), ("first_news", "bleeping"), ("kev_added", "cisa")]
    h, _ = bearer(db_session, mk_user(db_session))
    full = (await get(db_session, "/api/cves/CVE-2024-0001", headers=h)).json()["events"]
    assert [e["source"] for e in full] == ["nvd", "ransomware.live", "bleeping", "cisa"]
    assert set(full[0]) == {"kind", "occurred_at", "source", "detail"}


async def test_detail_events_restriction_applies_before_limit(db_session):
    cve(db_session, "CVE-2024-0001")
    for i in range(100):
        ev(db_session, "CVE-2024-0001", f"k{i}", "ransomware.live", 500 - i)
    ev(db_session, "CVE-2024-0001", "published", "nvd", 1)
    anon = (await get(db_session, "/api/cves/CVE-2024-0001")).json()["events"]
    assert [e["kind"] for e in anon] == ["published"]


async def test_detail_affected_versions_roundtrip(db_session):
    av = {"product": "widget", "vendor": "acme", "ecosystem": None, "introduced": "1.0",
          "fixed": "1.2", "last_affected": None, "source": "NVD"}
    cve(db_session, "CVE-2024-0001", affected_versions=[av, {"junk": 1}])
    body = (await get(db_session, "/api/cves/CVE-2024-0001")).json()
    assert body["affected_versions"] == [av]


async def test_detail_related_product_then_cwe_max4(db_session):
    cve(db_session, "CVE-2024-0001", affected=["Acme Widget"], cwes=["CWE-79"])
    cve(db_session, "CVE-2024-0002", affected=["Acme Widget"], cvss=5.0)
    cve(db_session, "CVE-2024-0003", affected=["Acme Widget"], cvss=9.0)
    cve(db_session, "CVE-2024-0004", affected=["Acme Widget"], kev=True, cvss=1.0)
    cve(db_session, "CVE-2024-0005", cwes=["CWE-79"], cvss=10.0)
    cve(db_session, "CVE-2024-0006", cwes=["CWE-79"], cvss=3.0)
    cve(db_session, "CVE-2024-0007", affected=["Other"], cwes=["CWE-1"])
    body = (await get(db_session, "/api/cves/CVE-2024-0001")).json()
    assert [r["cve_id"] for r in body["related"]] == [
        "CVE-2024-0004", "CVE-2024-0003", "CVE-2024-0002", "CVE-2024-0005"]
    assert set(body["related"][0]) == {"cve_id", "cvss", "kev", "epss_percentile", "product"}
    assert body["related"][0]["product"] == "Acme Widget"


async def test_detail_related_from_affected_versions_product(db_session):
    av = {"product": "libfoo", "source": "OSV"}
    cve(db_session, "CVE-2024-0001", affected_versions=[av])
    cve(db_session, "CVE-2024-0002", affected_versions=[av, {"product": "x", "source": "OSV"}])
    cve(db_session, "CVE-2024-0003", affected_versions=[{"product": "bar", "source": "OSV"}])
    body = (await get(db_session, "/api/cves/CVE-2024-0001")).json()
    assert [r["cve_id"] for r in body["related"]] == ["CVE-2024-0002"]


async def test_detail_geo_top_respects_range(db_session):
    cve(db_session, "CVE-2024-0001")
    n = 0
    for cc, days_ago, count in [("US", 1, 3), ("DE", 2, 2), ("FR", 3, 1), ("JP", 4, 1),
                                ("CN", 20, 9)]:
        for _ in range(count):
            n += 1
            geo(db_session, f"g{n}", cve_id="CVE-2024-0001", country_code=cc,
                observed_at=NOW - timedelta(days=days_ago))
    top = (await get(db_session, "/api/cves/CVE-2024-0001")).json()["geo_top"]
    assert top == [{"country_code": "US", "events": 3}, {"country_code": "DE", "events": 2},
                   {"country_code": "FR", "events": 1}]
    wide = (await get(db_session, "/api/cves/CVE-2024-0001?range=30d")).json()["geo_top"]
    assert wide[0] == {"country_code": "CN", "events": 9}


async def test_detail_exploit_reference_from_poc_event(db_session):
    cve(db_session, "CVE-2024-0001",
        references=[{"url": "https://a.test/ref", "tags": ["Vendor"]}])
    ev(db_session, "CVE-2024-0001", "poc_published", "exploitdb", 5, url="https://edb.test/1")
    ev(db_session, "CVE-2024-0001", "poc_published", "other", 4, url="https://edb.test/1")
    ev(db_session, "CVE-2024-0001", "poc_published", "bad", 3, url="javascript:alert(1)")
    ev(db_session, "CVE-2024-0001", "poc_published", "bad2", 2, url=7)
    refs = (await get(db_session, "/api/cves/CVE-2024-0001")).json()["references"]
    assert refs == [{"url": "https://a.test/ref", "tags": ["Vendor"]},
                    {"url": "https://edb.test/1", "tags": ["Exploit"]}]


async def test_detail_invalid_range_422(db_session):
    cve(db_session, "CVE-2024-0001")
    assert (await get(db_session, "/api/cves/CVE-2024-0001?range=1y")).status_code == 422
    assert (await get(db_session, "/api/cves/nope?range=7d")).status_code == 404


async def test_detail_updated_at_utc(db_session):
    cve(db_session, "CVE-2024-0001")
    body = (await get(db_session, "/api/cves/CVE-2024-0001")).json()
    assert body["updated_at"].endswith(("Z", "+00:00"))
