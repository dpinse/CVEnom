from datetime import UTC, date, datetime, timedelta

import pytest

from cvenom.collectors import base
from cvenom.collectors.kev import KevCollector


TODAY = datetime.now(UTC).date()
D1, D2, D3 = (TODAY - timedelta(days=n) for n in (3, 2, 1))
OLD = TODAY - timedelta(days=400)


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)


def _entry(cve, vendor="Acme", product="Widget", added=None):
    added = D1.isoformat() if added is None else added
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": f"{product} flaw",
        "dateAdded": added,
        "shortDescription": "Bad things.",
        "requiredAction": "Apply updates.",
        "dueDate": "2026-11-22",
        "knownRansomwareCampaignUse": "Unknown",
    }


def _feed(*entries):
    return {
        "catalogVersion": "2026.11.04",
        "dateReleased": "2026-11-04T00:00:00.000Z",
        "count": len(entries),
        "vulnerabilities": list(entries),
    }


def _three():
    return _feed(
        _entry("CVE-2026-1001", "Acme", "Widget", D1.isoformat()),
        _entry("CVE-2026-1002", "Globex", "Gadget", D2.isoformat()),
        _entry("CVE-2026-1003", "Initech", "Printer", D3.isoformat()),
    )


def test_normalize_maps_fields():
    res = KevCollector().normalize(_three())
    by_id = {c.cve_id: c for c in res.cves}
    assert set(by_id) == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}
    c = by_id["CVE-2026-1002"]
    assert c.kev is True
    assert c.kev_added == D2
    assert c.kev_source == "cisa"
    assert c.affected == ["Globex Gadget"]
    assert c.summary is None


def test_normalize_skips_malformed_entries():
    feed = _feed(
        _entry("CVE-2026-1001"),
        {"vendorProject": "X", "product": "Y", "dateAdded": "2026-11-01"},
        _entry("CVE-2026-1002", added="not-a-date"),
        _entry("CVE-2026-1003"),
    )
    res = KevCollector().normalize(feed)
    assert {c.cve_id for c in res.cves} == {"CVE-2026-1001", "CVE-2026-1003"}


def test_dead_diff_method_removed():
    # Seen-set diffing lives in seenstate.track_new (covered in test_seenstate.py).
    assert not hasattr(KevCollector, "diff")


def test_first_run_emits_no_events_and_populates_state():
    k = KevCollector()
    res = k.normalize(_three())
    assert res.events == []
    assert k.state["seen"] == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]
    assert len(res.cves) == 3


def test_second_run_with_new_entry_emits_one_event():
    k = KevCollector(state={"seen": ["CVE-2026-1001", "CVE-2026-1002"]})
    res = k.normalize(_three())
    assert res.events == [{"type": "kev_added", "cve_id": "CVE-2026-1003", "source": "cisa"}]
    assert k.state["seen"] == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]


def test_second_run_no_change_emits_nothing():
    k = KevCollector(state={"seen": ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]})
    assert k.normalize(_three()).events == []


def test_registered():
    assert base.REGISTRY["cisa_kev"] is KevCollector
    assert KevCollector.cadence_seconds == 3600


def test_truncated_feed_does_not_shrink_seen_or_replay():
    ids = ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]
    k = KevCollector(state={"seen": list(ids)})
    assert k.normalize(_feed()).events == []
    assert k.state["seen"] == ids
    assert k.normalize(_three()).events == []
    assert k.state["seen"] == ids


def test_non_dict_element_skipped():
    feed = _feed(_entry("CVE-2026-1001"), "garbage", None, 5, _entry("CVE-2026-1002"))
    res = KevCollector().normalize(feed)
    assert {c.cve_id for c in res.cves} == {"CVE-2026-1001", "CVE-2026-1002"}


@pytest.mark.parametrize("bad", [None, "CVE-2026-1001", 7, {"a": 1}])
def test_corrupt_seen_state_rebaselines_without_events(bad, caplog):
    k = KevCollector(state={"seen": bad})
    with caplog.at_level("WARNING"):
        res = k.normalize(_three())
    assert res.events == []
    assert "corrupt" in caplog.text and "cisa_kev" in caplog.text
    assert k.state["seen"] == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]


def test_invalid_cve_id_skipped_and_logged(caplog):
    feed = _feed(_entry("CVE-1<img src=x>"), _entry(" cve-2026-1001 "), _entry("CVE-26-1"))
    with caplog.at_level("WARNING"):
        res = KevCollector().normalize(feed)
    assert [c.cve_id for c in res.cves] == ["CVE-2026-1001"]
    assert "CVE-1<img src=x>" in caplog.text


def test_empty_first_run_leaves_seen_absent_then_full_run_baselines_silently():
    k = KevCollector()
    assert k.normalize(_feed()).events == []
    assert "seen" not in k.state
    k2 = KevCollector(state=k.state)
    assert k2.normalize(_three()).events == []
    assert k2.state["seen"] == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]


def test_truncated_first_baseline_then_full_feed_emits_only_recent():
    k = KevCollector()
    k.normalize(_feed(_entry("CVE-2026-1001", added=OLD.isoformat())))  # truncated baseline
    full = _feed(
        _entry("CVE-2026-1001", added=OLD.isoformat()),
        _entry("CVE-2026-1002", added=OLD.isoformat()),
        _entry("CVE-2026-1003", added=D3.isoformat()),
    )
    k2 = KevCollector(state=k.state)
    assert k2.normalize(full).events == [
        {"type": "kev_added", "cve_id": "CVE-2026-1003", "source": "cisa"}
    ]
    assert k2.state["seen"] == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]


def test_new_entry_older_than_max_age_is_silent(monkeypatch):
    from types import SimpleNamespace
    from cvenom.collectors import kev

    monkeypatch.setattr(kev, "get_settings", lambda: SimpleNamespace(kev_alert_max_age_days=1))
    k = KevCollector(state={"seen": ["CVE-2026-1001"]})
    res = k.normalize(_feed(_entry("CVE-2026-1001"), _entry("CVE-2026-1002", added=D1.isoformat())))
    assert res.events == []  # D1 is 3 days ago > 1-day max age
    assert "CVE-2026-1002" in k.state["seen"]


# --- detail fields (radar refinements, spec D) ---


def test_kev_maps_detail_fields():
    e = _entry("CVE-2026-1001")
    e["knownRansomwareCampaignUse"] = "Known"
    e["notes"] = "See vendor advisory."
    c = KevCollector().normalize(_feed(e)).cves[0]
    assert c.kev_name == "Widget flaw"
    assert c.kev_action == "Apply updates."
    assert c.kev_due == date(2026, 11, 22)
    assert c.kev_ransomware is True
    assert c.kev_notes == "See vendor advisory."
    e["knownRansomwareCampaignUse"] = "Unknown"
    assert KevCollector().normalize(_feed(e)).cves[0].kev_ransomware is False
    e["knownRansomwareCampaignUse"] = "weird"
    assert KevCollector().normalize(_feed(e)).cves[0].kev_ransomware is None
    e2 = _entry("CVE-2026-1002")
    e2["notes"] = 5
    e2["requiredAction"] = None
    c2 = KevCollector().normalize(_feed(e2)).cves[0]
    assert c2.kev_notes is None and c2.kev_action is None


def test_kev_bad_due_date_keeps_record():
    e = _entry("CVE-2026-1001")
    e["dueDate"] = "not-a-date"
    res = KevCollector().normalize(_feed(e))
    assert len(res.cves) == 1
    assert res.cves[0].kev_due is None
    e["dueDate"] = 12
    assert KevCollector().normalize(_feed(e)).cves[0].kev_due is None


def test_kev_rerun_backfills_existing_row(db_session):
    from sqlalchemy import insert

    from cvenom.models import Cve
    from cvenom.pipeline import ingest

    db_session.execute(insert(Cve).values(
        cve_id="CVE-2026-1001", kev=True, poc_badge=False, affected=[], summary="", kev_name=None,
    ))
    ingest(db_session, KevCollector().normalize(_feed(_entry("CVE-2026-1001"))))
    row = db_session.get(Cve, "CVE-2026-1001")
    db_session.refresh(row)
    assert row.kev_name == "Widget flaw"
    assert row.kev_action == "Apply updates."
