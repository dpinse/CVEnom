from datetime import date
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
    s = SimpleNamespace(vulncheck_api_token="tok-123")
    monkeypatch.setattr(vulncheck, "get_settings", lambda: s)
    return s


@pytest.fixture
def no_token(monkeypatch):
    s = SimpleNamespace(vulncheck_api_token=None)
    monkeypatch.setattr(vulncheck, "get_settings", lambda: s)
    return s


def _rec(cve, vendor="Acme", product="Widget", added="2026-11-01T00:00:00.000Z"):
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
            httpx.Response(200, json=_page([_rec(["CVE-2026-1"])], 1, 2)),
            httpx.Response(200, json=_page([_rec("CVE-2026-2")], 2, 2)),
        ]
    )
    res = await VulnCheckCollector().run()
    assert route.call_count == 2
    assert [r.request.url.params["page"] for r in route.calls] == ["1", "2"]
    assert {c.cve_id for c in res.cves} == {"CVE-2026-1", "CVE-2026-2"}
    assert len(fast_sleep) == 1


@respx.mock
async def test_pagination_terminates_on_empty_page(token):
    route = respx.get(VULNCHECK_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_rec("CVE-2026-1")], 1, 99)),
            httpx.Response(200, json=_page([], 2, 99)),
        ]
    )
    res = await VulnCheckCollector().run()
    assert route.call_count == 2
    assert {c.cve_id for c in res.cves} == {"CVE-2026-1"}


def test_malformed_records_skipped(token):
    raw = [
        _page(
            [
                _rec("CVE-2026-1"),
                "garbage",
                None,
                {"vendorProject": "X"},
                _rec(["CVE-2026-2", "", 5, "CVE-2026-3"]),
                _rec("CVE-2026-4", added="not-a-date"),
            ]
        )
    ]
    res = VulnCheckCollector().normalize(raw)
    assert {c.cve_id for c in res.cves} == {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4"}
    by_id = {c.cve_id: c for c in res.cves}
    assert by_id["CVE-2026-4"].kev_added is None


def test_missing_vendor_or_product_no_affected(token):
    rec = _rec("CVE-2026-1")
    del rec["product"]
    res = VulnCheckCollector().normalize([_page([rec])])
    assert res.cves[0].affected == []


def test_second_run_new_id_emits_event(token):
    k = VulnCheckCollector(state={"seen": ["CVE-2026-1"]})
    res = k.normalize([_page([_rec("CVE-2026-1"), _rec("CVE-2026-2")])])
    assert res.events == [{"type": "kev_added", "cve_id": "CVE-2026-2", "source": "vulncheck"}]
    assert k.state["seen"] == ["CVE-2026-1", "CVE-2026-2"]
