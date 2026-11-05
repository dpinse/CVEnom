import logging
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
import respx

from cvenom.collectors import base, vulncheck
from cvenom.collectors.vulncheck import VULNCHECK_URL, VulnCheckCollector


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    calls = []

    async def fake(delay):
        calls.append(delay)

    monkeypatch.setattr(base, "_sleep", fake)
    return calls


@pytest.fixture
def token(monkeypatch):
    s = SimpleNamespace(vulncheck_api_token="tok-123", kev_alert_max_age_days=14)
    monkeypatch.setattr(vulncheck, "get_settings", lambda: s)
    return s


@pytest.fixture
def no_token(monkeypatch):
    s = SimpleNamespace(vulncheck_api_token=None, kev_alert_max_age_days=14)
    monkeypatch.setattr(vulncheck, "get_settings", lambda: s)
    return s


RECENT = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00.000Z")
OLD = "2020-01-01T00:00:00.000Z"


def _rec(cve, vendor="Acme", product="Widget", added=RECENT):
    return {
        "cve": cve,
        "vendorProject": vendor,
        "product": product,
        "date_added": added,
        "vulncheck_reported_exploitation": [],
    }


def _page(records, page=1, total_pages=1):
    return {
        "_meta": {"total_documents": len(records), "page": page, "total_pages": total_pages},
        "data": records,
    }


def test_registered():
    assert base.REGISTRY["vulncheck_kev"] is VulnCheckCollector
    assert VulnCheckCollector.cadence_seconds == 3600


@respx.mock
async def test_no_token_returns_empty_and_no_http(no_token):
    route = respx.get(VULNCHECK_URL).mock(return_value=httpx.Response(200, json=_page([])))
    res = await VulnCheckCollector().run()
    assert res.cves == [] and res.events == [] and res.stories == []
    assert not route.called


@respx.mock
async def test_with_token_sends_bearer_and_expands_cves(token):
    route = respx.get(VULNCHECK_URL).mock(
        return_value=httpx.Response(
            200,
            json=_page(
                [
                    _rec(["CVE-2026-1001", "CVE-2026-1002"], "Acme", "Widget", "2026-11-01T00:00:00.000Z"),
                    _rec("CVE-2026-1003", "Globex", "Gadget", "2026-11-02"),
                ]
            ),
        )
    )
    res = await VulnCheckCollector().run()
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok-123"
    by_id = {c.cve_id: c for c in res.cves}
    assert set(by_id) == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}
    a = by_id["CVE-2026-1001"]
    assert a.kev is True and a.kev_source == "vulncheck"
    assert a.kev_added == date(2026, 11, 1)
    assert a.affected == ["Acme Widget"]
    assert a.summary is None
    assert by_id["CVE-2026-1003"].kev_added == date(2026, 11, 2)
    assert res.events == []  # first run baseline


@respx.mock
async def test_pagination_terminates_on_total_pages(token, fast_sleep):
    route = respx.get(VULNCHECK_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_rec(["CVE-2026-0001"])], 1, 2)),
            httpx.Response(200, json=_page([_rec("CVE-2026-0002")], 2, 2)),
        ]
    )
    res = await VulnCheckCollector().run()
    assert route.call_count == 2
    assert [r.request.url.params["page"] for r in route.calls] == ["1", "2"]
    assert {c.cve_id for c in res.cves} == {"CVE-2026-0001", "CVE-2026-0002"}
    assert len(fast_sleep) == 1


@respx.mock
async def test_pagination_terminates_on_empty_page(token):
    route = respx.get(VULNCHECK_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_rec("CVE-2026-0001")], 1, 99)),
            httpx.Response(200, json=_page([], 2, 99)),
        ]
    )
    res = await VulnCheckCollector().run()
    assert route.call_count == 2
    assert {c.cve_id for c in res.cves} == {"CVE-2026-0001"}


def test_malformed_records_skipped(token):
    raw = [
        _page(
            [
                _rec("CVE-2026-0001"),
                "garbage",
                None,
                {"vendorProject": "X"},
                _rec(["CVE-2026-0002", "", 5, "CVE-2026-0003"]),
                _rec("CVE-2026-0004", added="not-a-date"),
            ]
        )
    ]
    res = VulnCheckCollector().normalize(raw)
    assert {c.cve_id for c in res.cves} == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}
    by_id = {c.cve_id: c for c in res.cves}
    assert by_id["CVE-2026-0004"].kev_added is None


def test_missing_vendor_or_product_no_affected(token):
    rec = _rec("CVE-2026-0001")
    del rec["product"]
    res = VulnCheckCollector().normalize([_page([rec])])
    assert res.cves[0].affected == []


def test_second_run_new_id_emits_event(token):
    k = VulnCheckCollector(state={"seen": ["CVE-2026-0001"]})
    res = k.normalize([_page([_rec("CVE-2026-0001"), _rec("CVE-2026-0002")])])
    assert res.events == [{"type": "kev_added", "cve_id": "CVE-2026-0002", "source": "vulncheck"}]
    assert k.state["seen"] == ["CVE-2026-0001", "CVE-2026-0002"]


def test_invalid_cve_id_skipped_and_logged(token, caplog):
    raw = [_page([_rec(["CVE-1<img src=x>", "cve-2026-1001", "CVE-24-1"])])]
    with caplog.at_level("WARNING"):
        res = VulnCheckCollector().normalize(raw)
    assert [c.cve_id for c in res.cves] == ["CVE-2026-1001"]
    assert "CVE-1<img src=x>" in caplog.text


def test_old_new_id_silent_recent_new_id_emits(token):
    k = VulnCheckCollector(state={"seen": ["CVE-2026-0001"]})
    res = k.normalize(
        [_page([_rec("CVE-2026-0001"), _rec("CVE-2026-0002", added=OLD), _rec("CVE-2026-0003")])]
    )
    assert res.events == [{"type": "kev_added", "cve_id": "CVE-2026-0003", "source": "vulncheck"}]
    assert k.state["seen"] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]


def test_unknown_added_date_still_emits(token):
    k = VulnCheckCollector(state={"seen": ["CVE-2026-0001"]})
    res = k.normalize([_page([_rec("CVE-2026-0002", added="garbage")])])
    assert [e["cve_id"] for e in res.events] == ["CVE-2026-0002"]


def test_empty_first_run_leaves_seen_absent(token):
    k = VulnCheckCollector()
    assert k.normalize([_page([])]).events == []
    assert "seen" not in k.state


@respx.mock
async def test_truncation_at_max_pages_warns(token, monkeypatch, caplog):
    monkeypatch.setattr(vulncheck, "MAX_PAGES", 2)
    route = respx.get(VULNCHECK_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_rec("CVE-2026-0001")], 1, 5)),
            httpx.Response(200, json=_page([_rec("CVE-2026-0002")], 2, 5)),
            httpx.Response(200, json=_page([_rec("CVE-2026-0003")], 3, 5)),
        ]
    )
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.vulncheck"):
        await VulnCheckCollector().fetch()
    assert route.call_count == 2
    assert any("MAX_PAGES" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("meta", [{}, {"total_pages": "3"}, {"total_pages": None}, None])
@respx.mock
async def test_missing_or_non_int_total_pages_warns(token, caplog, meta):
    page = {"data": [_rec("CVE-2026-0001")]}
    if meta is not None:
        page["_meta"] = meta
    respx.get(VULNCHECK_URL).mock(return_value=httpx.Response(200, json=page))
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.vulncheck"):
        await VulnCheckCollector().fetch()
    assert any("total_pages" in r.getMessage() for r in caplog.records)


@respx.mock
async def test_complete_pagination_does_not_warn(token, caplog):
    respx.get(VULNCHECK_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_rec("CVE-2026-0001")], 1, 2)),
            httpx.Response(200, json=_page([_rec("CVE-2026-0002")], 2, 2)),
        ]
    )
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.vulncheck"):
        await VulnCheckCollector().fetch()
    assert not caplog.records
