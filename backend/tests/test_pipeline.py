from datetime import datetime, timedelta, timezone

import psycopg.errors
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
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-109618", published=now, cvss=9.2, kev=True, kev_added=now.date())]))
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
        raise IntegrityError("INSERT", {}, psycopg.errors.UniqueViolation("dup"))

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
        NormalizedCve(cve_id="CVE-2026-9100", kev=True, kev_added=NOW.date(), cvss=5.0),
        NormalizedCve(cve_id="CVE-2026-9101", kev=True, kev_added=NOW.date(), cvss=9.0, epss_percentile=0.99,
                      published=NOW - timedelta(days=1)),
        NormalizedCve(cve_id="CVE-2026-9102", kev=True, kev_added=NOW.date(), cvss=7.0),
    ]))
    views = lane_views(db_session, NOW)
    assert [v.cve_id for v in views[Lane.EXPLOITED]] == ["CVE-2026-9101", "CVE-2026-9102", "CVE-2026-9100"]
    assert views[Lane.LIKELY] == []  # KEV rows are never 'likely next'


def test_non_unique_integrity_error_is_not_retried(db_session, monkeypatch):
    n = {"c": 0}

    def fk(session, data):
        n["c"] += 1
        raise IntegrityError("INSERT", {}, psycopg.errors.ForeignKeyViolation("fk"))

    monkeypatch.setattr(pipeline, "upsert_cve", fk)
    with pytest.raises(IntegrityError):
        ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-5100")]))
    assert n["c"] == 1


def test_story_race_real_unique_conflict_retries_and_skips(db_session, monkeypatch):
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-5200", kev=True)]))
    db_session.execute(insert(Story).values(
        url="https://x/race", content_hash="other", source="X", title="theirs", summary="", published=NOW))
    real = pipeline.find_existing_story
    n = {"c": 0}

    def miss_first(session, url, digest):
        n["c"] += 1
        return None if n["c"] == 1 else real(session, url, digest)

    monkeypatch.setattr(pipeline, "find_existing_story", miss_first)
    ingest(db_session, CollectorResult(
        cves=[NormalizedCve(cve_id="CVE-2026-5201")],
        stories=[_story("https://x/race", "mine CVE-2026-5200")]))
    assert n["c"] == 2  # unique violation on url -> savepoint rollback -> retry saw winner
    assert db_session.query(Story).count() == 1
    assert db_session.query(Story).one().title == "theirs"
    assert db_session.get(Cve, "CVE-2026-5201") is not None  # batch not poisoned
    assert db_session.get(Cve, "CVE-2026-5200").kev is True


def test_stub_cve_race_inside_link_story_retries(db_session, monkeypatch):
    real = pipeline.link_story
    _insert_cve(db_session, "CVE-2026-5300", cvss=6.0)
    n = {"c": 0}

    def racing(session, story, ids):
        n["c"] += 1
        if n["c"] == 1:
            session.add(Cve(cve_id="CVE-2026-5300", kev=False, poc_badge=False, affected=[], summary=""))
            session.flush()  # real PK conflict
        return real(session, story, ids)

    monkeypatch.setattr(pipeline, "link_story", racing)
    ingest(db_session, CollectorResult(stories=[_story("https://x/stub", "t CVE-2026-5300")]))
    assert n["c"] == 2
    assert db_session.query(Story).count() == 1
    assert db_session.query(StoryCveLink).filter_by(cve_id="CVE-2026-5300").count() == 1
    assert db_session.get(Cve, "CVE-2026-5300").cvss == 6.0


def test_enrich_only_skips_stories(db_session):
    ingest(db_session, CollectorResult(
        stories=[_story("https://x/e", "t CVE-2026-5400")]), enrich_only=True)
    assert db_session.query(Story).count() == 0
    assert db_session.get(Cve, "CVE-2026-5400") is None


def test_affected_entries_sanitized(db_session):
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-5500", affected=["php <script>alert(1)</script>8.1", "nginx"])]))
    aff = db_session.get(Cve, "CVE-2026-5500").affected
    assert all("<" not in a and "alert" not in a for a in aff)
    assert "nginx" in aff


def test_lane_tie_order_is_by_cve_id_and_naive_now_is_utc(db_session):
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-9202", kev=True, kev_added=NOW.date()),
        NormalizedCve(cve_id="CVE-2026-9200", kev=True, kev_added=NOW.date()),
        NormalizedCve(cve_id="CVE-2026-9201", kev=True, kev_added=NOW.date()),
    ]))
    for now in (NOW, NOW.replace(tzinfo=None)):
        ids = [v.cve_id for v in lane_views(db_session, now)[Lane.EXPLOITED]]
        assert ids == ["CVE-2026-9200", "CVE-2026-9201", "CVE-2026-9202"]


def test_exact_boundaries_consistent_between_sql_and_scoring(db_session):
    from cvenom.config import get_settings
    cfg = get_settings()
    ingest(db_session, CollectorResult(
        cves=[
            NormalizedCve(cve_id="CVE-2026-9300", cvss=cfg.fresh_cvss_floor, published=NOW),
            NormalizedCve(cve_id="CVE-2026-9301", cvss=9.9,
                          published=NOW - timedelta(days=7)),
            NormalizedCve(cve_id="CVE-2026-9302", epss_percentile=cfg.epss_percentile_threshold, published=NOW - timedelta(days=cfg.likely_window_days)),
            NormalizedCve(cve_id="CVE-2026-9303"),
        ],
        stories=[_story("https://x/b", "edge CVE-2026-9303",
                        published=NOW - timedelta(days=7))]))
    views = lane_views(db_session, NOW)
    fresh = {v.cve_id for v in views[Lane.FRESH]}
    assert {"CVE-2026-9300", "CVE-2026-9301"} <= fresh
    assert [v.cve_id for v in views[Lane.LIKELY]] == ["CVE-2026-9302"]
    loud = views[Lane.LOUD]
    assert [v.cve_id for v in loud] == ["CVE-2026-9303"] and loud[0].recent_story_count == 1


# --- KEV overlap across CISA and VulnCheck (#1) ---

from datetime import date as _date


def _kev_result(cve_id, source, added):
    return CollectorResult(
        cves=[NormalizedCve(cve_id=cve_id, kev=True, kev_source=source, kev_added=added)],
        events=[{"type": "kev_added", "cve_id": cve_id, "source": source}],
    )


@pytest.mark.parametrize(
    "first, second",
    [
        (("cisa", _date(2026, 11, 3)), ("vulncheck", _date(2026, 11, 1))),
        (("vulncheck", _date(2026, 11, 1)), ("cisa", _date(2026, 11, 3))),
    ],
    ids=["cisa_then_vulncheck", "vulncheck_then_cisa"],
)
def test_kev_overlap_one_event_stable_source_earliest_date(db_session, first, second):
    cid = "CVE-2026-7001"
    events = []
    # Two full hourly cycles of both feeds: no flip-flopping, no duplicate events.
    for _ in range(2):
        for part in (first, second):
            new = ingest(db_session, _kev_result(cid, *part))
            pipeline.persist_events(db_session, new, source_default="x")
            events += new
    assert [e["cve_id"] for e in events] == [cid]
    assert events[0]["source"] == first[0]
    row = db_session.get(Cve, cid)
    assert row.kev_source == "cisa"
    assert row.kev_added == _date(2026, 11, 1)


def test_reingest_already_kev_cve_emits_nothing(db_session):
    _insert_cve(db_session, "CVE-2026-7002", kev=True, kev_source="cisa",
                kev_alerted_at=datetime.now(timezone.utc))
    res = _kev_result("CVE-2026-7002", "cisa", _date(2026, 11, 3))
    assert ingest(db_session, res) == []


def test_kev_event_for_new_cve_passes_and_other_events_untouched(db_session):
    _insert_cve(db_session, "CVE-2026-7003", kev=False)  # known, but not yet KEV
    res = CollectorResult(
        cves=[NormalizedCve(cve_id="CVE-2026-7003", kev=True, kev_source="cisa")],
        events=[
            {"type": "kev_added", "cve_id": "CVE-2026-7003", "source": "cisa"},
            {"type": "other", "cve_id": "CVE-2026-7003"},
        ],
    )
    first = ingest(db_session, res)
    assert first == res.events
    pipeline.persist_events(db_session, first, source_default="cisa")  # stamps kev_alerted_at
    # Second time around the CVE is KEV in the DB: kev_added dropped, other kept.
    assert ingest(db_session, res) == [{"type": "other", "cve_id": "CVE-2026-7003"}]


def test_osv_later_run_without_fix_does_not_downgrade_patch(db_session):
    from cvenom.collectors.osv import OsvCollector

    fixed = {
        "id": "GHSA-8080-8080-8080",
        "aliases": ["CVE-2026-8080"],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "p"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}],
    }
    unfixed = {
        "id": "GO-2026-8080",
        "aliases": ["CVE-2026-8080"],
        "affected": [{"package": {"ecosystem": "Go", "name": "q"},
                      "ranges": [{"events": [{"introduced": "0"}]}]}],
    }
    _insert_cve(db_session, "CVE-2026-8080")
    ingest(db_session, OsvCollector().normalize([fixed]), enrich_only=True)
    ingest(db_session, OsvCollector().normalize([unfixed]), enrich_only=True)
    row = db_session.get(Cve, "CVE-2026-8080")
    assert row.patch_available is True
    assert sorted(row.affected) == ["Go:q", "PyPI:p"]


# --- enrich_only cost (#6) ---


def test_enrich_path_issues_o_chunks_selects_and_no_savepoints(db_session):
    from sqlalchemy import event

    existing = [f"CVE-2026-{i:05d}" for i in range(0, 2500, 50)]  # 50 known
    for cid in existing:
        _insert_cve(db_session, cid)
    db_session.flush()
    res = CollectorResult(
        cves=[NormalizedCve(cve_id=f"CVE-2026-{i:05d}", epss=0.5, epss_percentile=0.5) for i in range(2500)]
    )
    stmts: list[str] = []

    def count(conn, cursor, statement, params, context, executemany):
        stmts.append(statement.lstrip().split(None, 1)[0].upper())

    bind = db_session.connection()
    event.listen(bind, "before_cursor_execute", count)
    try:
        ingest(db_session, res, enrich_only=True)
    finally:
        event.remove(bind, "before_cursor_execute", count)

    selects = stmts.count("SELECT")
    assert selects <= 3, stmts[:20]  # ceil(2500 / 1000) chunked IN lookups
    assert "SAVEPOINT" not in stmts
    assert len(stmts) <= 3 + len(existing) + 5  # chunk SELECTs + one UPDATE per known row
    assert db_session.query(Cve).count() == len(existing)  # nothing stub-created
    assert db_session.get(Cve, existing[1]).epss == 0.5



@pytest.mark.parametrize("enrich", [False, True])
def test_empty_affected_entries_filtered_after_sanitizing(db_session, enrich):
    cid = "CVE-2026-5501"
    if enrich:
        _insert_cve(db_session, cid)
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id=cid, affected=["<script>alert(1)</script>", "", "   ", "<b></b>", "nginx"])]),
        enrich_only=enrich)
    assert db_session.get(Cve, cid).affected == ["nginx"]


# ---- CISA listing alerts when no KEV alert was ever sent (kev_alerted_at)

import logging
from datetime import UTC
from sqlalchemy import select
from cvenom.collectors.seenstate import track_new
from cvenom.models import AlertEvent


def _kev_events(db_session, cid):
    return db_session.scalars(
        select(AlertEvent).where(AlertEvent.cve_id == cid, AlertEvent.type == "kev_added")
    ).all()


def _run_cisa(db_session, cid, state, *, added=None):
    """One CISA collector cycle for ``cid`` via the real seen-set/recency logic."""
    added = added or datetime.now(UTC).date()
    events = track_new(state, {cid}, added_dates={cid: added}, max_age_days=14,
                       source="cisa", collector_name="kev", logger=logging.getLogger("t"))
    res = CollectorResult(
        cves=[NormalizedCve(cve_id=cid, kev=True, kev_source="cisa", kev_added=added)],
        events=events)
    out = ingest(db_session, res)
    pipeline.persist_events(db_session, out, source_default="kev")
    db_session.refresh(db_session.get(Cve, cid))
    return out


def test_cisa_alerts_after_vulncheck_silent_baseline(db_session):
    cid = "CVE-2026-9101"
    # VulnCheck first-run baseline: marks KEV, emits no event.
    assert ingest(db_session, _silent_vc(cid)) == []
    assert db_session.get(Cve, cid).kev_alerted_at is None
    state = {"seen": ["CVE-2026-0001"]}  # CISA already baselined, X is new and recent
    out = _run_cisa(db_session, cid, state)
    assert [e["source"] for e in out] == ["cisa"]
    assert len(_kev_events(db_session, cid)) == 1
    assert db_session.get(Cve, cid).kev_alerted_at is not None
    # CISA re-run with a lost seen-set: already alerted -> nothing new.
    assert _run_cisa(db_session, cid, {"seen": ["CVE-2026-0001"]}) == []
    assert len(_kev_events(db_session, cid)) == 1


def _silent_vc(cid):
    return CollectorResult(
        cves=[NormalizedCve(cve_id=cid, kev=True, kev_source="vulncheck",
                            kev_added=datetime.now(UTC).date())])


def test_cisa_dropped_after_vulncheck_alerted(db_session):
    cid = "CVE-2026-9102"
    res = _kev_result(cid, "vulncheck", datetime.now(UTC).date())
    pipeline.persist_events(db_session, ingest(db_session, res), source_default="vulncheck")
    assert len(_kev_events(db_session, cid)) == 1
    assert _run_cisa(db_session, cid, {"seen": ["CVE-2026-0001"]}) == []
    assert len(_kev_events(db_session, cid)) == 1


def test_cisa_dropped_after_cisa_already_alerted(db_session):
    cid = "CVE-2026-9103"
    assert len(_run_cisa(db_session, cid, {"seen": ["CVE-2026-0001"]})) == 1
    assert _run_cisa(db_session, cid, {"seen": ["CVE-2026-0001"]}) == []
    assert len(_kev_events(db_session, cid)) == 1


def test_vulncheck_event_still_dropped_for_known_kev_never_alerted(db_session):
    cid = "CVE-2026-9104"
    _insert_cve(db_session, cid, kev=True, kev_source="cisa")  # kev_alerted_at NULL
    assert ingest(db_session, _kev_result(cid, "vulncheck", _date(2026, 11, 3))) == []


def test_old_cisa_listing_still_gated_by_recency(db_session):
    cid = "CVE-2026-9105"
    ingest(db_session, _silent_vc(cid))
    out = _run_cisa(db_session, cid, {"seen": ["CVE-2026-0001"]},
                    added=datetime.now(UTC).date() - timedelta(days=60))
    assert out == []
    assert _kev_events(db_session, cid) == []


def test_ingest_sanitizes_new_text_and_story_details(db_session):
    payload = "x < y <script>alert(1)</script>"
    cve = NormalizedCve(
        cve_id="CVE-2026-9500", kev_name=payload, kev_action=payload, kev_notes=payload,
        cvss_vector="CVSS:3.1/<b>AV:N</b>", cwes=["CWE-79"],
        references=[{"url": "https://a.example/x?a=1&b=2", "tags": ["<i>Patch</i>", "<script>x</script>"]}],
    )
    story = NormalizedStory(url="https://www.ransomware.live/id/abc", source="ransomware.live",
                            title="Acme hit", summary="s", published=NOW,
                            details={"victim": payload, "nested": {"k": ["<b>v</b>"]}})
    ingest(db_session, CollectorResult(cves=[cve], stories=[story]))
    db_session.expire_all()
    row = db_session.get(Cve, "CVE-2026-9500")
    for value in (row.kev_name, row.kev_action, row.kev_notes):
        assert value == "x &lt; y"
    assert row.cvss_vector == "CVSS:3.1/AV:N"
    assert row.cwes == ["CWE-79"]
    assert row.references == [{"url": "https://a.example/x?a=1&amp;b=2", "tags": ["Patch"]}]
    s = db_session.query(Story).one()
    assert s.details == {"victim": "x &lt; y", "nested": {"k": ["v"]}}
    assert s.url == "https://www.ransomware.live/id/abc"  # raw URL column is stored as validated


def test_ingest_drops_vector_that_grows_past_255_when_escaped(db_session):
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-9501", cvss_vector="&" * 200),
        NormalizedCve(cve_id="CVE-2026-9502", cvss_vector="CVSS:3.1/AV:N"),
    ]))
    assert db_session.get(Cve, "CVE-2026-9501").cvss_vector is None
    assert db_session.get(Cve, "CVE-2026-9502").cvss_vector == "CVSS:3.1/AV:N"


def test_lane_views_exploited_ranks_priority_over_date(db_session):
    from datetime import date
    _insert_cve(db_session, "CVE-2026-9400", kev=True, kev_added=date(2026, 10, 1),
                epss_percentile=0.99, cvss=9.9)
    _insert_cve(db_session, "CVE-2026-9401", kev=True, kev_added=date(2026, 10, 10),
                epss_percentile=0.10, cvss=5.0)
    ids = [v.cve_id for v in lane_views(db_session, NOW, "30d")[Lane.EXPLOITED]]
    assert ids == ["CVE-2026-9400", "CVE-2026-9401"]  # high EPSS beats newer KEV


def test_loud_counts_stories_in_range(db_session):
    ingest(db_session, CollectorResult(
        cves=[NormalizedCve(cve_id="CVE-2026-9600")],
        stories=[_story("https://x/five", "five days CVE-2026-9600", published=NOW - timedelta(days=5))]))
    loud7 = lane_views(db_session, NOW, "7d")[Lane.LOUD]
    assert [v.cve_id for v in loud7] == ["CVE-2026-9600"]
    assert loud7[0].recent_story_count == 1
    assert lane_views(db_session, NOW, "24h")[Lane.LOUD] == []


def test_kev_row_is_never_likely_or_fresh_in_lane_views(db_session):
    _insert_cve(db_session, "CVE-2026-9610", kev=True, kev_added=NOW.date() - timedelta(days=20),
                epss_percentile=0.99, cvss=9.8, published=NOW - timedelta(hours=2))
    v7 = lane_views(db_session, NOW, "7d")
    assert all(v7[lane] == [] for lane in Lane)
    v30 = lane_views(db_session, NOW, "30d")
    assert [v.cve_id for v in v30[Lane.EXPLOITED]] == ["CVE-2026-9610"]
    assert v30[Lane.LIKELY] == [] and v30[Lane.FRESH] == []


# --- cve_event timeline hooks ---


def _events(session, kind):
    from sqlalchemy import select

    from cvenom.models import CveEvent
    return list(session.scalars(
        select(CveEvent).where(CveEvent.kind == kind).order_by(CveEvent.source)))


def test_ingest_writes_first_news_once(db_session):
    early, late = NOW - timedelta(days=2), NOW - timedelta(hours=1)
    stories = [
        NormalizedStory(url="https://x/a", source="THN", title="CVE-2026-8800 later", summary="s", published=late),
        NormalizedStory(url="https://x/b", source="THN", title="CVE-2026-8800 earlier", summary="s2", published=early),
        NormalizedStory(url="https://x/c", source="BC", title="CVE-2026-8800 bc", summary="s3", published=late),
    ]
    ingest(db_session, CollectorResult(stories=stories))
    ingest(db_session, CollectorResult(stories=stories))
    rows = _events(db_session, "first_news")
    assert [(r.source, r.occurred_at) for r in rows] == [("BC", late), ("THN", early)]
    assert rows[1].detail == {"title": "CVE-2026-8800 earlier", "url": "https://x/b"}


def test_ingest_passes_collector_label(db_session):
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-8801", published=NOW)]),
           collector="nvd")
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-8802", published=NOW)]),
           collector="osv")
    assert sorted((r.cve_id, r.source) for r in _events(db_session, "published")) == [
        ("CVE-2026-8801", "NVD"), ("CVE-2026-8802", "OSV")]


def test_enrich_only_events_only_for_known_cves(db_session):
    _insert_cve(db_session, "CVE-2026-8803")
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-8803", epss=0.9, epss_percentile=0.99),
        NormalizedCve(cve_id="CVE-2026-8804", epss=0.9, epss_percentile=0.99),
    ]), enrich_only=True, collector="epss")
    assert [r.cve_id for r in _events(db_session, "epss_crossed")] == ["CVE-2026-8803"]


def test_result_cve_events_are_persisted(db_session):
    from cvenom.schemas import NormalizedCveEvent
    ev = NormalizedCveEvent(cve_id="CVE-2026-8805", kind="poc_published", occurred_at=NOW,
                            source="Exploit-DB")
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-8805")], cve_events=[ev]))
    assert [r.source for r in _events(db_session, "poc_published")] == ["Exploit-DB"]


def _av(product, source, **kw):
    return {"product": product, "source": source, **kw}


def test_upsert_replaces_per_source(db_session):
    from cvenom.db import upsert_cve

    def run(*entries):
        upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-6001", affected_versions=list(entries)))
        return db_session.get(Cve, "CVE-2026-6001").affected_versions

    run(_av("a", "NVD", fixed="1"))
    got = run(_av("b", "OSV", fixed="2"))
    assert [(e["product"], e["source"]) for e in got] == [("a", "NVD"), ("b", "OSV")]
    got = run(_av("c", "NVD", fixed="3"), _av("c", "NVD", fixed="3"))
    assert [(e["product"], e["source"]) for e in got] == [("b", "OSV"), ("c", "NVD")]
    # None (not provided) leaves the stored entries alone
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-6001"))
    assert len(db_session.get(Cve, "CVE-2026-6001").affected_versions) == 2


def test_ingest_sanitizes_affected_versions(db_session):
    ingest(db_session, CollectorResult(cves=[NormalizedCve(
        cve_id="CVE-2026-6002",
        affected_versions=[
            _av("<b>x</b> & y", "NVD", vendor="<i>v</i>", fixed="1.0"),
            _av("e" * 125 + "&<>", "NVD"),  # escaping pushes it over 128: dropped
        ],
    )]))
    got = db_session.get(Cve, "CVE-2026-6002").affected_versions
    assert len(got) == 1
    assert "<" not in got[0]["product"] and "x" in got[0]["product"]
    assert got[0]["product"].endswith("&amp; y") and got[0]["vendor"] == "v"


def test_first_news_event_source_sanitized_and_truncated(db_session):
    from cvenom.models import CveEvent

    source = "Odd\x07<b>Source</b> " + "z" * 100
    ingest(db_session, CollectorResult(stories=[NormalizedStory(
        url="https://example.com/odd", source=source, title="CVE-2026-6003 exploited",
        summary="s", published=NOW)]))
    ev = db_session.query(CveEvent).filter_by(cve_id="CVE-2026-6003", kind="first_news").one()
    assert len(ev.source) == 64
    assert ev.source == pipeline.sanitize_text(source)[:64]
    assert "\x07" not in ev.source and "<" not in ev.source


def test_first_news_event_source_falls_back_to_unknown_when_empty(db_session):
    from cvenom.models import CveEvent

    ingest(db_session, CollectorResult(stories=[NormalizedStory(
        url="https://example.com/nosrc", source="<b></b>", title="CVE-2026-6004 exploited",
        summary="s", published=NOW)]))
    ev = db_session.query(CveEvent).filter_by(cve_id="CVE-2026-6004", kind="first_news").one()
    assert ev.source == "unknown"


def test_year_one_kev_added_does_not_poison_the_batch(db_session):
    from datetime import date

    bad = NormalizedCve(cve_id="CVE-2026-9701", kev=True, kev_source="vulncheck",
                        kev_added=date(1, 1, 1), published=datetime(1, 1, 1, tzinfo=timezone.utc))
    assert bad.kev_added is None and bad.published is None  # bounded at the schema
    good = NormalizedCve(cve_id="CVE-2026-9702", kev=True, kev_source="cisa",
                         kev_added=date(2026, 10, 20))
    ingest(db_session, CollectorResult(cves=[bad, good]), collector="vulncheck_kev")
    assert db_session.get(Cve, "CVE-2026-9701") is not None
    assert [e.cve_id for e in _events(db_session, "kev_added")] == ["CVE-2026-9702"]


def test_one_invalid_derived_event_is_skipped_not_fatal(db_session, monkeypatch):
    # Even if a bad value slips past the schema, derivation skips only that event.
    from cvenom import timeline

    good = NormalizedCve(cve_id="CVE-2026-9704", published=NOW - timedelta(days=1))
    poisoned = NormalizedCve(cve_id="CVE-2026-9703", published=NOW - timedelta(days=1))
    object.__setattr__(poisoned, "published", datetime(1, 1, 1, tzinfo=timezone.utc))
    out = timeline.derived_events(
        [poisoned, good], collector="nvd", now=NOW, cfg=pipeline.get_settings()
    )
    assert [e.cve_id for e in out] == ["CVE-2026-9704"]


def _kev(cve_id, **kw):
    return NormalizedCve(cve_id=cve_id, published=NOW - timedelta(days=1), kev=True,
                         kev_added=NOW.date(), **kw)


def test_exploited_lane_is_ranked_by_priority(db_session):
    ingest(db_session, CollectorResult(cves=[
        _kev("CVE-2026-7001", cvss=5.0, epss_percentile=0.2),
        _kev("CVE-2026-7002", epss_percentile=0.95),            # unscored, high EPSS
        _kev("CVE-2026-7003", cvss=4.0, kev_ransomware=True),   # ransomware first
        _kev("CVE-2026-7004"),                                   # NULLs last
        _kev("CVE-2026-7006", cvss=5.0, epss_percentile=0.2),   # tie with 7001 -> id order
    ]))
    views = lane_views(db_session, NOW)
    assert [v.cve_id for v in views[Lane.EXPLOITED]] == [
        "CVE-2026-7003", "CVE-2026-7002", "CVE-2026-7001", "CVE-2026-7006", "CVE-2026-7004"]
    assert all(v.cve_id not in {x.cve_id for x in views[Lane.EXPLOITED]} for v in views[Lane.LIKELY])


def test_exploited_lane_recent_boost_and_expiry(db_session):
    old = NOW.date() - timedelta(days=2)
    ingest(db_session, CollectorResult(cves=[
        NormalizedCve(cve_id="CVE-2026-7020", published=NOW, kev=True, kev_added=old,
                      epss_percentile=0.99, cvss=9.8),
        NormalizedCve(cve_id="CVE-2026-7021", published=NOW, kev=True,
                      kev_added=NOW.date() - timedelta(days=1)),          # null EPSS/CVSS, recent
        NormalizedCve(cve_id="CVE-2026-7022", published=NOW, kev=True, kev_added=NOW.date(),
                      cvss=5.0, epss_percentile=0.5),
    ]))
    ids = [v.cve_id for v in lane_views(db_session, NOW)[Lane.EXPLOITED]]
    assert ids == ["CVE-2026-7022", "CVE-2026-7021", "CVE-2026-7020"]
    # a day later the yesterday-row ages out of the boost and falls behind the p99 row
    later = NOW + timedelta(days=1)
    ids = [v.cve_id for v in lane_views(db_session, later, "30d")[Lane.EXPLOITED]]
    assert ids == ["CVE-2026-7022", "CVE-2026-7020", "CVE-2026-7021"]


def test_kev_with_high_epss_stays_out_of_likely(db_session):
    ingest(db_session, CollectorResult(cves=[_kev("CVE-2026-7010", cvss=9.0, epss_percentile=0.99)]))
    views = lane_views(db_session, NOW)
    assert [v.cve_id for v in views[Lane.EXPLOITED]] == ["CVE-2026-7010"]
    assert views[Lane.LIKELY] == []
