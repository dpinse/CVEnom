def test_upsert_merges_signals_across_feeds(db_session):
    from cvenom.models import Cve
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    from datetime import datetime, timezone
    pub = datetime(2026,10,21,tzinfo=timezone.utc)
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-109618", published=pub, cvss=9.2))
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-109618", epss=0.97, epss_percentile=0.99, kev=True, kev_source="cisa"))
    row = db_session.get(Cve, "CVE-2026-109618")
    assert row.cvss == 9.2 and row.epss == 0.97 and row.kev is True
    assert db_session.query(Cve).count() == 1  # merged, not duplicated

def test_kev_flag_is_not_cleared_by_later_feed(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    from cvenom.models import Cve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0001", kev=True))
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0001", kev=False))
    assert db_session.get(Cve, "CVE-2026-0001").kev is True


def test_affected_is_unioned_across_upserts(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0002", affected=["a", "b"]))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0002", affected=["b", "c"]))
    assert sorted(row.affected) == ["a", "b", "c"]


def test_poc_badge_is_sticky(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0003", poc_badge=True))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0003", poc_badge=False))
    assert row.poc_badge is True


def test_null_and_blank_fields_do_not_clobber(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0004", cvss=7.5, summary="orig"))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0004", cvss=None, summary=""))
    assert row.cvss == 7.5 and row.summary == "orig"


def test_kev_added_keeps_earliest_date(db_session):
    from datetime import date
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    cid = "CVE-2026-0005"
    upsert_cve(db_session, NormalizedCve(cve_id=cid, kev=True, kev_added=date(2026, 11, 3)))
    row = upsert_cve(db_session, NormalizedCve(cve_id=cid, kev=True, kev_added=date(2026, 11, 1)))
    assert row.kev_added == date(2026, 11, 1)
    row = upsert_cve(db_session, NormalizedCve(cve_id=cid, kev=True, kev_added=date(2026, 11, 4)))
    assert row.kev_added == date(2026, 11, 1)
    row = upsert_cve(db_session, NormalizedCve(cve_id=cid, kev=True, kev_added=None))
    assert row.kev_added == date(2026, 11, 1)


def test_kev_source_cisa_is_sticky(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0006", kev=True, kev_source="cisa"))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0006", kev=True, kev_source="vulncheck"))
    assert row.kev_source == "cisa"


def test_kev_source_cisa_overwrites_vulncheck(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0007", kev=True, kev_source="vulncheck"))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0007", kev=True, kev_source="cisa"))
    assert row.kev_source == "cisa"
