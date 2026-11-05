from datetime import date

import pytest

from cvenom.collectors import base
from cvenom.collectors.kev import KevCollector


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)


def _entry(cve, vendor="Acme", product="Widget", added="2026-11-01"):
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
        _entry("CVE-2026-1001", "Acme", "Widget", "2026-11-01"),
        _entry("CVE-2026-1002", "Globex", "Gadget", "2026-11-02"),
        _entry("CVE-2026-1003", "Initech", "Printer", "2026-11-03"),
    )


def test_normalize_maps_fields():
    res = KevCollector().normalize(_three())
    by_id = {c.cve_id: c for c in res.cves}
    assert set(by_id) == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}
    c = by_id["CVE-2026-1002"]
    assert c.kev is True
    assert c.kev_added == date(2026, 11, 2)
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


def test_diff_emits_only_new_entries():
    k = KevCollector()
    first = k.diff(seen=set(), current={"CVE-2026-109618", "CVE-2026-109619"})
    assert {e["cve_id"] for e in first} == {"CVE-2026-109618", "CVE-2026-109619"}
    second = k.diff(
        seen={"CVE-2026-109618", "CVE-2026-109619"},
        current={"CVE-2026-109618", "CVE-2026-109619"},
    )
    assert second == []


def test_diff_event_shape_sorted():
    ev = KevCollector().diff(set(), {"CVE-2026-2", "CVE-2026-1"})
    assert ev == [
        {"type": "kev_added", "cve_id": "CVE-2026-1", "source": "cisa"},
        {"type": "kev_added", "cve_id": "CVE-2026-2", "source": "cisa"},
    ]


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
