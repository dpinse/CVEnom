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
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-1", kev=True))
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-1", kev=False))
    assert db_session.get(Cve, "CVE-2026-1").kev is True


def test_affected_is_unioned_across_upserts(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-2", affected=["a", "b"]))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-2", affected=["b", "c"]))
    assert sorted(row.affected) == ["a", "b", "c"]


def test_poc_badge_is_sticky(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-3", poc_badge=True))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-3", poc_badge=False))
    assert row.poc_badge is True


def test_null_and_blank_fields_do_not_clobber(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-4", cvss=7.5, summary="orig"))
    row = upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-4", cvss=None, summary=""))
    assert row.cvss == 7.5 and row.summary == "orig"
