from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import event, text

from cvenom.models import Cve, GeoEvent, Story, StoryCveLink
from cvenom.readmodels import cve_velocity, geo_summary, loud_stories

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


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
    _cve(db_session, "CVE-2026-1", datetime(2026, 11, 4, 23, 30, tzinfo=UTC))
    _cve(db_session, "CVE-2026-2", datetime(2026, 11, 5, 0, 30, tzinfo=UTC))
    db_session.flush()
    r = cve_velocity(db_session, NOW, days=3)
    assert [s["count"] for s in r["series"]] == [0, 1, 1]


def test_velocity_independent_of_session_timezone(db_session):
    _cve(db_session, "CVE-2026-1", datetime(2026, 11, 4, 23, 30, tzinfo=UTC))
    _cve(db_session, "CVE-2026-2", datetime(2026, 11, 5, 0, 30, tzinfo=UTC))
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
    _story(db_session, 1, 100)
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
