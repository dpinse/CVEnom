from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import insert, select

from cvenom.config import Settings
from cvenom.models import Cve, CveEvent
from cvenom.schemas import CveReference, NormalizedCve, NormalizedCveEvent
from cvenom.timeline import (
    MAX_EVENT_DETAIL_BYTES,
    derived_events,
    insert_cve_events,
    is_nuclei_reference,
)

NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)
CFG = Settings()


def _cve(session, cve_id="CVE-2026-7000"):
    session.execute(insert(Cve).values(cve_id=cve_id, kev=False, poc_badge=False, affected=[], summary=""))


def _ev(kind="kev_added", at=NOW, source="CISA KEV", cve_id="CVE-2026-7000", detail=None):
    return NormalizedCveEvent(cve_id=cve_id, kind=kind, occurred_at=at, source=source, detail=detail or {})


def _rows(session, kind=None):
    q = select(CveEvent)
    if kind:
        q = q.where(CveEvent.kind == kind)
    return list(session.scalars(q.order_by(CveEvent.id)))


def test_derived_events_cover_each_signal():
    cve = NormalizedCve(
        cve_id="CVE-2026-7001", published=NOW - timedelta(days=1), kev=True,
        kev_added=date(2026, 10, 20), kev_source="cisa", epss_percentile=0.97,
        references=[CveReference(
            url="https://github.com/ProjectDiscovery/nuclei-templates/blob/main/http/cves/x.yaml")],
    )
    evs = derived_events([cve], collector="nvd", now=NOW, cfg=CFG)
    assert {(e.kind, e.source) for e in evs} == {
        ("published", "NVD"), ("kev_added", "CISA KEV"), ("epss_crossed", "FIRST EPSS"),
        ("detection", "Nuclei templates"),
    }
    kev = next(e for e in evs if e.kind == "kev_added")
    assert kev.occurred_at == datetime(2026, 10, 20, tzinfo=timezone.utc)
    assert next(e for e in evs if e.kind == "epss_crossed").detail == {"percentile": 0.97}


def test_published_label_names_the_collector_and_nvd_modified_only_for_nvd():
    cve = NormalizedCve(cve_id="CVE-2026-7002", published=NOW, last_modified=NOW)
    osv = derived_events([cve], collector="osv", now=NOW, cfg=CFG)
    assert [(e.kind, e.source) for e in osv] == [("published", "OSV")]
    nvd = derived_events([cve], collector="nvd", now=NOW, cfg=CFG)
    assert {e.kind for e in nvd} == {"published", "nvd_modified"}
    assert derived_events([cve], collector=None, now=NOW, cfg=CFG)[0].source == "CVEnom"


def test_epss_below_threshold_no_event():
    cve = NormalizedCve(cve_id="CVE-2026-7003", epss_percentile=0.5)
    assert derived_events([cve], collector="epss", now=NOW, cfg=CFG) == []


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/projectdiscovery/nuclei-templates/blob/main/a.yaml", True),
    ("https://GITHUB.com/projectdiscovery/nuclei-templates/x", True),
    ("https://github.com/projectdiscovery/nuclei/x", False),
    ("https://evil.example/github.com/projectdiscovery/nuclei-templates/x", False),
    ("https://github.com.evil.example/projectdiscovery/nuclei-templates/x", False),
])
def test_is_nuclei_reference(url, expected):
    assert is_nuclei_reference(url) is expected


def test_insert_is_idempotent_and_first_wins(db_session):
    _cve(db_session)
    first = NOW - timedelta(days=2)
    insert_cve_events(db_session, [_ev(at=first)])
    insert_cve_events(db_session, [_ev(at=NOW)])
    rows = _rows(db_session, "kev_added")
    assert len(rows) == 1 and rows[0].occurred_at == first


def test_batch_duplicates_keep_earliest(db_session):
    _cve(db_session)
    early = NOW - timedelta(days=3)
    insert_cve_events(db_session, [_ev(at=NOW), _ev(at=early)])
    assert [r.occurred_at for r in _rows(db_session)] == [early]


def test_nvd_modified_moves_forward_only(db_session):
    _cve(db_session)
    t1, t2 = NOW - timedelta(days=2), NOW
    insert_cve_events(db_session, [_ev("nvd_modified", t1, "NVD")])
    insert_cve_events(db_session, [_ev("nvd_modified", t2, "NVD")])
    assert _rows(db_session)[0].occurred_at == t2
    insert_cve_events(db_session, [_ev("nvd_modified", t1, "NVD")])
    assert _rows(db_session)[0].occurred_at == t2
    assert len(_rows(db_session)) == 1


def test_first_news_earliest_story_wins_per_source(db_session):
    _cve(db_session)
    early = NOW - timedelta(days=2)
    insert_cve_events(db_session, [_ev("first_news", NOW, "THN", detail={"title": "late"})])
    insert_cve_events(db_session, [_ev("first_news", early, "THN", detail={"title": "early"})])
    insert_cve_events(db_session, [_ev("first_news", NOW, "THN", detail={"title": "later"})])
    (row,) = _rows(db_session)
    assert row.occurred_at == early and row.detail == {"title": "early"}


def test_unknown_cve_events_dropped(db_session):
    _cve(db_session)
    n = insert_cve_events(db_session, [_ev(cve_id="CVE-2026-7999"), _ev()])
    assert n == 1 and [r.cve_id for r in _rows(db_session)] == ["CVE-2026-7000"]


def test_detail_oversize_becomes_empty(db_session):
    _cve(db_session)
    insert_cve_events(db_session, [_ev(detail={"title": "x" * 3000})])
    assert MAX_EVENT_DETAIL_BYTES == 2048
    assert _rows(db_session)[0].detail == {}


def test_detail_sanitized(db_session):
    _cve(db_session)
    insert_cve_events(
        db_session,
        [_ev(source="<b>Src</b>", detail={"title": "hi <script>alert(1)</script><i>x</i>"})],
    )
    row = _rows(db_session)[0]
    assert "<" not in row.source and row.source == "Src"
    assert "<script" not in row.detail["title"] and "<i>" not in row.detail["title"]


def test_event_schema_rejects_bad_input():
    with pytest.raises(ValueError):
        _ev(kind="fix_released")
    with pytest.raises(ValueError):
        _ev(source="a\x00b")
    with pytest.raises(ValueError):
        _ev(source="x" * 65)
