from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

from cvenom import pipeline
from cvenom.collectors.base import CollectorResult
from cvenom.models import Cve, Story, StoryCveLink
from cvenom.pipeline import ingest, lane_views
from cvenom.schemas import NormalizedCve, NormalizedStory
from cvenom.scoring import Lane

NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)


def _story(url, title, published=NOW, summary="s"):
    return NormalizedStory(url=url, source="THN", title=title, summary=summary, published=published)


def _insert_cve(session, cve_id, **kw):
    values = dict(cve_id=cve_id, kev=False, poc_badge=False, affected=[], summary="")
    values.update(kw)
    session.execute(insert(Cve).values(**values))


def test_ingest_is_idempotent_and_links_stories(db_session):
    pub = datetime(2026, 10, 21, tzinfo=timezone.utc)
    r = CollectorResult(
        cves=[NormalizedCve(cve_id="CVE-2026-109618", published=pub, cvss=9.2, kev=True)],
        stories=[NormalizedStory(url="https://x/a", source="THN", title="PHP2Shell CVE-2026-109618", summary="rce", published=pub)])
    ingest(db_session, r); ingest(db_session, r)  # twice
    assert db_session.query(Story).count() == 1
    assert db_session.query(StoryCveLink).count() == 1


def test_lane_views_place_kev_in_exploited(db_session):
    now = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-109618", published=now, cvss=9.2, kev=True)]))
    views = lane_views(db_session, now)
    assert any(v.cve_id == "CVE-2026-109618" for v in views[Lane.EXPLOITED])


def test_ingest_returns_events_unchanged(db_session):
    events = [{"type": "kev_added", "cve_id": "CVE-2026-1111"}]
    assert ingest(db_session, CollectorResult(events=events)) == events


def test_race_real_pk_conflict_rolls_back_savepoint_and_retry_merges(db_session, monkeypatch):
    """First attempt hits a genuine PK conflict inside the savepoint; the retry merges."""
    real = pipeline.upsert_cve
    _insert_cve(db_session, "CVE-2026-5001", cvss=7.0, kev=True, affected=["old"], summary="theirs")
    n = {"calls": 0}

    def racing(session, data):
        n["calls"] += 1
        if n["calls"] == 1:
            # Identity map misses the row another collector inserted -> real IntegrityError.
            session.add(Cve(cve_id=data.cve_id, kev=False, poc_badge=False, affected=[], summary=""))
            session.flush()
        return real(session, data)

    monkeypatch.setattr(pipeline, "upsert_cve", racing)
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-5001", epss_percentile=0.97, affected=["new"], summary="mine")]))
    assert n["calls"] == 2  # retry path ran
    row = db_session.get(Cve, "CVE-2026-5001")
    assert row.kev is True and row.cvss == 7.0  # their data kept
    assert row.epss_percentile == 0.97 and row.summary == "mine"  # ours merged
    assert row.affected == ["old", "new"]


def test_race_persistent_integrity_error_propagates(db_session, monkeypatch):
    def always(session, data):
        raise IntegrityError("INSERT", {}, Exception("dup"))

    monkeypatch.setattr(pipeline, "upsert_cve", always)
    with pytest.raises(IntegrityError):
        ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-5002")]))


def test_enrich_only_updates_existing_and_skips_unknown(db_session):
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-6000", cvss=8.0)]))
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-6000", epss_percentile=0.99),
        NormalizedCve(cve_id="CVE-2026-6001", epss_percentile=0.99),
    ]), enrich_only=True)
    assert db_session.get(Cve, "CVE-2026-6000").epss_percentile == 0.99
    assert db_session.get(Cve, "CVE-2026-6001") is None


def test_sanitizes_story_and_cve_text(db_session):
    ingest(db_session, CollectorResult(
        cves=[NormalizedCve(cve_id="CVE-2026-7000", summary="bad <script>alert(1)</script>text")],
        stories=[_story("https://x/s", "Hi <script>alert(2)</script>CVE-2026-7000", summary="<b>bold</b> <img src=x onerror=y>")]))
    cve_summary = db_session.get(Cve, "CVE-2026-7000").summary
    assert "<" not in cve_summary and "alert" not in cve_summary
    s = db_session.query(Story).one()
    assert "<" not in s.title and "alert" not in s.title
    assert "<" not in s.summary
    assert db_session.query(StoryCveLink).count() == 1  # extraction saw the raw text


def test_extraction_on_raw_hash_on_sanitized(db_session):
    from cvenom.textutil import content_hash, sanitize_text
    t, s = "x <i>CVE-2026-7100</i>", "<p>y</p>"
    ingest(db_session, CollectorResult(stories=[_story("https://x/h", t, summary=s)]))
    row = db_session.query(Story).one()
    assert row.content_hash == content_hash(sanitize_text(t), sanitize_text(s))
    assert db_session.query(StoryCveLink).filter_by(cve_id="CVE-2026-7100").count() == 1


def test_story_dedup_by_content_hash_with_new_url(db_session):
    ingest(db_session, CollectorResult(stories=[_story("https://x/1", "Same title")]))
    ingest(db_session, CollectorResult(stories=[_story("https://x/2", "Same title")]))
    assert db_session.query(Story).count() == 1


def test_quiet_foil_only_in_fresh_and_old_cve_in_no_lane(db_session):
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-8000", published=NOW - timedelta(hours=1), cvss=9.5),
        NormalizedCve(cve_id="CVE-2026-8001", published=NOW - timedelta(days=400), cvss=9.8, epss_percentile=0.1),
    ]))
    views = lane_views(db_session, NOW)
    assert [v.cve_id for v in views[Lane.FRESH]] == ["CVE-2026-8000"]
    for lane in (Lane.EXPLOITED, Lane.LIKELY, Lane.LOUD):
        assert views[lane] == []
    assert all(v.cve_id != "CVE-2026-8001" for vs in views.values() for v in vs)


def test_all_lane_keys_present_when_empty(db_session):
    assert set(lane_views(db_session, NOW)) == set(Lane)


def test_loud_window_and_recent_story_count(db_session):
    ingest(db_session, CollectorResult(
        cves=[NormalizedCve(cve_id="CVE-2026-9000"), NormalizedCve(cve_id="CVE-2026-9001")],
        stories=[
            _story("https://x/old", "old CVE-2026-9000", published=NOW - timedelta(hours=200)),
            _story("https://x/n1", "new1 CVE-2026-9001", published=NOW - timedelta(hours=1)),
            _story("https://x/n2", "new2 CVE-2026-9001", published=NOW - timedelta(hours=2)),
            _story("https://x/o2", "older CVE-2026-9001", published=NOW - timedelta(hours=300)),
        ]))
    loud = lane_views(db_session, NOW)[Lane.LOUD]
    assert [v.cve_id for v in loud] == ["CVE-2026-9001"]
    assert loud[0].recent_story_count == 2


def test_lane_ordering_by_heat_rank_and_multi_lane(db_session):
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-9100", kev=True, cvss=5.0),
        NormalizedCve(cve_id="CVE-2026-9101", kev=True, cvss=9.0, epss_percentile=0.99),
        NormalizedCve(cve_id="CVE-2026-9102", kev=True, cvss=7.0),
    ]))
    views = lane_views(db_session, NOW)
    assert [v.cve_id for v in views[Lane.EXPLOITED]] == ["CVE-2026-9101", "CVE-2026-9102", "CVE-2026-9100"]
    assert [v.cve_id for v in views[Lane.LIKELY]] == ["CVE-2026-9101"]
