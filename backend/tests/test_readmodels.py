from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import event, text

from cvenom.models import Cve, CveEvent, GeoEvent, Story, StoryCveLink
from cvenom.pipeline import lane_views
from cvenom.readmodels import (
    cve_velocity,
    cve_volume,
    geo_summary,
    loud_stories,
    summary_counts,
)
from cvenom.scoring import Lane

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)


def _cve(session, cid, published):
    session.add(Cve(cve_id=cid, published=published))


def _add_cves(session, day_counts):
    """day_counts: {days_ago: n} published at 10:00 UTC."""
    i = 0
    for ago, n in day_counts.items():
        d = (NOW - timedelta(days=ago)).replace(hour=10)
        for _ in range(n):
            i += 1
            _cve(session, f"CVE-2026-{i:05d}", d)
    session.flush()


# ---- velocity ----
def test_velocity_zero_fills(db_session):
    _add_cves(db_session, {0: 2, 3: 1})
    r = cve_velocity(db_session, NOW, days=5)
    assert len(r["series"]) == 5
    assert [s["count"] for s in r["series"]] == [0, 1, 0, 0, 2]
    assert r["series"][-1]["day"] == date(2026, 11, 5)
    assert r["series"][0]["day"] == date(2026, 11, 1)
    assert r["current"] == 2


def test_velocity_rising_true(db_session):
    _add_cves(db_session, {ago: (1 if ago >= 7 else 3) for ago in range(14)})
    assert cve_velocity(db_session, NOW, days=14)["rising"] is True


@pytest.mark.parametrize("flat", [True, False])
def test_velocity_not_rising(db_session, flat):
    _add_cves(db_session, {ago: (2 if flat else (3 if ago >= 7 else 1)) for ago in range(14)})
    assert cve_velocity(db_session, NOW, days=14)["rising"] is False


def test_velocity_short_window_never_rising(db_session):
    _add_cves(db_session, {0: 9, 1: 5})
    assert cve_velocity(db_session, NOW, days=7)["rising"] is False


def test_velocity_utc_day_boundary(db_session):
    _cve(db_session, "CVE-2026-1", datetime(2026, 11, 4, 23, 30, tzinfo=timezone.utc))
    _cve(db_session, "CVE-2026-2", datetime(2026, 11, 5, 0, 30, tzinfo=timezone.utc))
    db_session.flush()
    r = cve_velocity(db_session, NOW, days=3)
    assert [s["count"] for s in r["series"]] == [0, 1, 1]


def test_velocity_independent_of_session_timezone(db_session):
    _cve(db_session, "CVE-2026-1", datetime(2026, 11, 4, 23, 30, tzinfo=timezone.utc))
    _cve(db_session, "CVE-2026-2", datetime(2026, 11, 5, 0, 30, tzinfo=timezone.utc))
    db_session.flush()
    db_session.execute(text("SET LOCAL TIME ZONE 'America/New_York'"))
    r = cve_velocity(db_session, NOW, days=3)
    assert [s["count"] for s in r["series"]] == [0, 1, 1]


def test_velocity_naive_now_treated_as_utc(db_session):
    _add_cves(db_session, {0: 1})
    r = cve_velocity(db_session, NOW.replace(tzinfo=None), days=2)
    assert [s["count"] for s in r["series"]] == [0, 1]


def test_velocity_ignores_null_and_out_of_range(db_session):
    _cve(db_session, "CVE-2026-1", None)
    _cve(db_session, "CVE-2026-2", NOW - timedelta(days=30))
    _cve(db_session, "CVE-2026-3", NOW + timedelta(days=2))
    db_session.flush()
    r = cve_velocity(db_session, NOW, days=7)
    assert sum(s["count"] for s in r["series"]) == 0
    assert r["current"] == 0


# ---- geo ----
def _geo(session, i, cc, kind, mag, ago_h=1):
    session.add(GeoEvent(source="t", external_id=str(i), kind=kind, country_code=cc,
                         magnitude=mag, observed_at=NOW - timedelta(hours=ago_h)))


def test_geo_summary_aggregates_and_filters(db_session):
    _geo(db_session, 1, "US", "scan", 2.0, 1)
    _geo(db_session, 2, "US", "scan", 3.0, 2)
    _geo(db_session, 3, "US", "outage", 1.0)
    _geo(db_session, 4, None, "scan", 99.0)
    _geo(db_session, 5, "DE", "scan", 50.0, ago_h=48)
    db_session.flush()
    r = geo_summary(db_session, NOW)
    assert r == [
        {"country_code": "US", "kind": "scan", "magnitude": 5.0, "events": 2,
         "last_seen": NOW - timedelta(hours=1)},
        {"country_code": "US", "kind": "outage", "magnitude": 1.0, "events": 1,
         "last_seen": NOW - timedelta(hours=1)},
    ]
    assert isinstance(r[0]["magnitude"], float) and isinstance(r[0]["events"], int)


def test_geo_summary_window_param(db_session):
    _geo(db_session, 1, "DE", "scan", 1.0, ago_h=48)
    db_session.flush()
    assert geo_summary(db_session, NOW) == []
    assert len(geo_summary(db_session, NOW, window_hours=72)) == 1


def test_geo_summary_stable_ordering(db_session):
    _geo(db_session, 1, "FR", "b", 1.0)
    _geo(db_session, 2, "FR", "a", 1.0)
    _geo(db_session, 3, "DE", "z", 1.0)
    _geo(db_session, 4, "CN", "x", 9.0)
    db_session.flush()
    r = geo_summary(db_session, NOW)
    assert [(x["country_code"], x["kind"]) for x in r] == [
        ("CN", "x"), ("DE", "z"), ("FR", "a"), ("FR", "b")]


# ---- loud stories ----
def _story(session, i, ago_h, title="t"):
    s = Story(url=f"http://x/{i}", content_hash=str(i), source="src",
              title=f"{title}{i}", summary="s &amp; s",
              published=NOW - timedelta(hours=ago_h))
    session.add(s)
    session.flush()
    return s


def _link(session, story, cve_id):
    if session.get(Cve, cve_id) is None:
        session.add(Cve(cve_id=cve_id))
        session.flush()
    session.add(StoryCveLink(story_id=story.id, cve_id=cve_id))
    session.flush()


def test_loud_includes_cveless_and_links_sorted(db_session):
    a = _story(db_session, 1, 1)
    b = _story(db_session, 2, 2)
    _link(db_session, b, "CVE-2026-9")
    _link(db_session, b, "CVE-2026-1")
    r = loud_stories(db_session, NOW)
    assert [x["url"] for x in r] == [a.url, b.url]
    assert r[0]["cve_ids"] == []
    assert r[1]["cve_ids"] == ["CVE-2026-1", "CVE-2026-9"]
    assert set(r[0]) == {"title", "summary", "url", "source", "published", "cve_ids"}
    assert r[0]["summary"] == "s &amp; s"


def test_loud_window_and_order(db_session):
    _story(db_session, 1, 200)  # outside the default 7d range
    new = _story(db_session, 2, 1)
    same = _story(db_session, 3, 1)  # same published, higher id first
    r = loud_stories(db_session, NOW)
    assert [x["url"] for x in r] == [same.url, new.url]


def test_loud_limit_and_clamp(db_session):
    for i in range(5):
        _story(db_session, i, i + 1)
    assert len(loud_stories(db_session, NOW, limit=2)) == 2
    assert len(loud_stories(db_session, NOW, limit=0)) == 1
    assert len(loud_stories(db_session, NOW, limit=1000)) == 5
    for i in range(5, 120):
        _story(db_session, i, 1)
    assert len(loud_stories(db_session, NOW, limit=1000)) == 100


def test_loud_no_n_plus_one(db_session):
    for i in range(20):
        s = _story(db_session, i, 1)
        _link(db_session, s, f"CVE-2026-{i}")
    selects = []

    def count(conn, cursor, statement, *a):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    engine = db_session.get_bind()
    event.listen(engine, "before_cursor_execute", count)
    try:
        r = loud_stories(db_session, NOW, limit=20)
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert len(r) == 20
    assert len(selects) <= 2


# ---- summary / volume ----
def test_summary_counts_each_figure(db_session):
    today = NOW.date()
    old = NOW - timedelta(days=60)
    db = db_session
    # new_kev: in 7d vs out
    db.add(Cve(cve_id="CVE-2026-0001", published=old, kev=True, kev_added=today - timedelta(days=7)))
    db.add(Cve(cve_id="CVE-2026-0002", published=old, kev=True, kev_added=today - timedelta(days=8)))
    # kev_due_soon: today+7 counts, today+8 and yesterday do not
    db.add(Cve(cve_id="CVE-2026-0003", published=old, kev=True, kev_added=today - timedelta(days=90),
               kev_due=today + timedelta(days=7)))
    db.add(Cve(cve_id="CVE-2026-0004", published=old, kev=True, kev_added=today - timedelta(days=90),
               kev_due=today + timedelta(days=8)))
    db.add(Cve(cve_id="CVE-2026-0005", published=old, kev=True, kev_added=today - timedelta(days=90),
               kev_due=today - timedelta(days=1)))
    # new_critical: cvss>=9 not KEV in range; KEV, <9 and out-of-range excluded
    db.add(Cve(cve_id="CVE-2026-0006", published=NOW - timedelta(days=2), cvss=9.0))
    db.add(Cve(cve_id="CVE-2026-0007", published=NOW - timedelta(days=2), cvss=8.9))
    db.add(Cve(cve_id="CVE-2026-0008", published=NOW - timedelta(days=8), cvss=9.8))
    db.add(Cve(cve_id="CVE-2026-0009", published=NOW - timedelta(days=2), cvss=9.8, kev=True,
               kev_added=today - timedelta(days=90)))
    # public_exploits: distinct CVEs with poc_published in range (two sources = one CVE)
    db.add(Cve(cve_id="CVE-2026-0010", published=old))
    db.add(Cve(cve_id="CVE-2026-0011", published=old))
    db.flush()
    for cid, src, ago, kind in [
        ("CVE-2026-0010", "a", 1, "poc_published"),
        ("CVE-2026-0010", "b", 2, "poc_published"),
        ("CVE-2026-0011", "a", 8, "poc_published"),
        ("CVE-2026-0006", "a", 1, "kev_added"),
    ]:
        db.add(CveEvent(cve_id=cid, kind=kind, source=src, occurred_at=NOW - timedelta(days=ago)))
    db.flush()
    r = summary_counts(db, NOW, "7d")
    assert r["range"] == "7d"
    assert r["new_kev"] == 1
    assert r["kev_due_soon"] == 1
    assert r["new_critical"] == 1
    assert r["public_exploits"] == 1
    # kev_due_soon ignores the range; a wider range widens poc
    assert summary_counts(db, NOW, "30d")["kev_due_soon"] == 1
    assert summary_counts(db, NOW, "30d")["public_exploits"] == 2


def test_summary_counts_equal_lane_totals(db_session):
    today = NOW.date()
    for i in range(3):
        db_session.add(Cve(cve_id=f"CVE-2026-1{i:03d}", published=NOW - timedelta(days=40),
                           kev=True, kev_added=today - timedelta(days=i * 4)))
        db_session.add(Cve(cve_id=f"CVE-2026-2{i:03d}", published=NOW - timedelta(days=i * 4),
                           cvss=9.5))
    db_session.flush()
    for rng in ("24h", "7d", "14d", "30d"):
        views = lane_views(db_session, NOW, rng)
        s = summary_counts(db_session, NOW, rng)
        assert s["new_kev"] == len(views[Lane.EXPLOITED])
        assert s["new_critical"] == len(views[Lane.FRESH])


def test_summary_latest_kev_added(db_session):
    assert summary_counts(db_session, NOW, "7d")["latest_kev_added"] is None
    db_session.add(Cve(cve_id="CVE-2026-0001", kev=True, kev_added=date(2026, 1, 2)))
    db_session.add(Cve(cve_id="CVE-2026-0002", kev=True, kev_added=date(2026, 3, 4)))
    db_session.flush()
    assert summary_counts(db_session, NOW, "7d")["latest_kev_added"] == date(2026, 3, 4)


def test_volume_daily_buckets_and_severity(db_session):
    db = db_session
    for cid, cvss, ago in [
        ("CVE-2026-0001", 9.8, 0), ("CVE-2026-0002", 9.0, 0), ("CVE-2026-0003", 7.0, 1),
        ("CVE-2026-0004", 4.0, 1), ("CVE-2026-0005", 3.9, 2), ("CVE-2026-0006", None, 0),
        ("CVE-2026-0007", 9.8, 20),
    ]:
        db.add(Cve(cve_id=cid, cvss=cvss, published=NOW - timedelta(days=ago)))
    db.flush()
    r = cve_volume(db, NOW, "7d")
    assert r["unit"] == "day" and len(r["buckets"]) == 7
    last = r["buckets"][-1]
    assert last["start"] == datetime(2026, 11, 5, tzinfo=timezone.utc)
    assert (last["crit"], last["high"], last["med"], last["low"]) == (2, 0, 0, 0)
    assert (r["buckets"][-2]["high"], r["buckets"][-2]["med"]) == (1, 1)
    assert r["buckets"][-3]["low"] == 1
    assert r["total"] == 5 and r["unscored"] == 1
    assert cve_volume(db, NOW, "30d")["total"] == 6


def test_volume_24h_hourly(db_session):
    db_session.add(Cve(cve_id="CVE-2026-0001", cvss=8.0, published=NOW + timedelta(minutes=30)))
    db_session.add(Cve(cve_id="CVE-2026-0002", cvss=8.0, published=NOW - timedelta(hours=23)))
    db_session.add(Cve(cve_id="CVE-2026-0003", cvss=8.0, published=NOW - timedelta(hours=24)))
    db_session.flush()
    r = cve_volume(db_session, NOW, "24h")
    assert r["unit"] == "hour" and len(r["buckets"]) == 24
    assert r["buckets"][-1]["start"] == datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
    assert r["buckets"][-1]["high"] == 1 and r["buckets"][0]["high"] == 1
    assert r["total"] == 2
