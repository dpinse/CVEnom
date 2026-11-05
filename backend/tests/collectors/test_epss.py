import httpx
import pytest
import respx

from cvenom.collectors import base, epss
from cvenom.collectors.base import REGISTRY
from cvenom.collectors.epss import EPSS_URL, EpssCollector


def _rec(cve, e="0.5", p="0.6"):
    return {"cve": cve, "epss": e, "percentile": p, "date": "2026-11-04"}


def _page(data, total, offset=0):
    return {"status": "OK", "total": total, "offset": offset, "limit": 10000, "data": data}


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    calls = []

    async def fake(delay):
        calls.append(delay)

    monkeypatch.setattr(base, "_sleep", fake)
    monkeypatch.setattr(epss, "_sleep", fake)
    return calls


def test_normalize_converts_strings_to_floats():
    raw = [_page([_rec("CVE-2026-1001", "0.97", "0.99"), _rec("CVE-2026-1002", "0.0004", "0.1")], 2)]
    res = EpssCollector().normalize(raw)
    by_id = {c.cve_id: c for c in res.cves}
    assert by_id["CVE-2026-1001"].epss == 0.97
    assert by_id["CVE-2026-1001"].epss_percentile == 0.99
    assert isinstance(by_id["CVE-2026-1002"].epss, float)
    assert by_id["CVE-2026-1001"].kev is False
    assert by_id["CVE-2026-1001"].cvss is None


def test_normalize_skips_malformed_records():
    raw = [
        _page(
            [
                _rec("CVE-2026-1001"),
                {"epss": "0.1", "percentile": "0.2"},
                _rec("CVE-2026-1002", e="abc"),
                _rec("CVE-2026-1003", p=None),
                _rec("CVE-2026-1004"),
            ],
            5,
        )
    ]
    ids = [c.cve_id for c in EpssCollector().normalize(raw).cves]
    assert ids == ["CVE-2026-1001", "CVE-2026-1004"]


@respx.mock
async def test_fetch_paginates_with_advancing_offset(monkeypatch, fast_sleep):
    monkeypatch.setattr(epss, "PAGE_SIZE", 2)
    route = respx.get(EPSS_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_rec("CVE-2026-0001"), _rec("CVE-2026-0002")], 5, 0)),
            httpx.Response(200, json=_page([_rec("CVE-2026-0003"), _rec("CVE-2026-0004")], 5, 2)),
            httpx.Response(200, json=_page([_rec("CVE-2026-0005")], 5, 4)),
        ]
    )
    raw = await EpssCollector().fetch()
    offsets = [r.url.params["offset"] for r in (c.request for c in route.calls)]
    assert offsets == ["0", "2", "4"]
    assert all(r.request.url.params["limit"] == "2" for r in route.calls)
    assert len(fast_sleep) == 2
    ids = [c.cve_id for c in EpssCollector().normalize(raw).cves]
    assert ids == [f"CVE-2026-{i:04d}" for i in range(1, 6)]


@respx.mock
async def test_fetch_stops_on_empty_page_even_if_total_larger():
    route = respx.get(EPSS_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_rec("CVE-2026-0001")], 99, 0)),
            httpx.Response(200, json=_page([], 99, 1)),
        ]
    )
    raw = await EpssCollector().fetch()
    assert route.call_count == 2
    assert [c.cve_id for c in EpssCollector().normalize(raw).cves] == ["CVE-2026-0001"]


def test_enrich_only_and_registration():
    assert EpssCollector.enrich_only is True
    assert REGISTRY["epss"] is EpssCollector
    assert EpssCollector.name == "epss"
    assert EpssCollector.cadence_seconds == 7200


def test_normalize_skips_nan_inf_and_out_of_range():
    raw = [
        _page(
            [
                _rec("CVE-2026-1001"),
                _rec("CVE-2026-1002", e="nan"),
                _rec("CVE-2026-1003", p="inf"),
                _rec("CVE-2026-1004", p="1.5"),
                _rec("CVE-2026-1005", e="-0.2"),
                _rec("CVE-2026-1006", e="1", p="0"),
            ],
            6,
        )
    ]
    ids = [c.cve_id for c in EpssCollector().normalize(raw).cves]
    assert ids == ["CVE-2026-1001", "CVE-2026-1006"]


# --- score-date short-circuit (#6) ---


def _dated(cve, day):
    return {"cve": cve, "epss": "0.5", "percentile": "0.6", "date": day}


@respx.mock
async def test_unchanged_score_date_short_circuits_after_first_page(monkeypatch):
    monkeypatch.setattr(epss, "PAGE_SIZE", 2)
    route = respx.get(EPSS_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_dated("CVE-2026-0001", "2026-11-04"), _dated("CVE-2026-0002", "2026-11-04")], 5)),
            httpx.Response(200, json=_page([_dated("CVE-2026-0003", "2026-11-04")], 5, 2)),
        ]
    )
    c = EpssCollector(state={"score_date": "2026-11-04"})
    res = await c.run()
    assert route.call_count == 1
    assert c.last_error is None  # successful, empty run
    assert res.cves == []
    assert c.state["score_date"] == "2026-11-04"


@respx.mock
async def test_changed_score_date_fetches_all_and_updates_state(monkeypatch):
    monkeypatch.setattr(epss, "PAGE_SIZE", 2)
    route = respx.get(EPSS_URL).mock(
        side_effect=[
            httpx.Response(200, json=_page([_dated("CVE-2026-0001", "2026-11-05"), _dated("CVE-2026-0002", "2026-11-05")], 3)),
            httpx.Response(200, json=_page([_dated("CVE-2026-0003", "2026-11-05")], 3, 2)),
        ]
    )
    c = EpssCollector(state={"score_date": "2026-11-04"})
    res = await c.run()
    assert route.call_count == 2
    assert [x.cve_id for x in res.cves] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert c.state["score_date"] == "2026-11-05"


@respx.mock
async def test_first_run_without_score_date_fetches_and_stores_it():
    respx.get(EPSS_URL).mock(
        return_value=httpx.Response(200, json=_page([_dated("CVE-2026-0001", "2026-11-05")], 1))
    )
    c = EpssCollector()
    res = await c.run()
    assert [x.cve_id for x in res.cves] == ["CVE-2026-0001"]
    assert c.state["score_date"] == "2026-11-05"


# --- poison records must not fail the run (#8) ---


@pytest.mark.parametrize("poison", ["garbage", None, 5, ["CVE-2026-0009"], {"cve": 7, "epss": "0.1", "percentile": "0.1"}])
def test_non_dict_or_malformed_record_skipped_others_kept(poison):
    raw = [_page([_rec("CVE-2026-1001"), poison, _rec("CVE-2026-1002")], 3)]
    ids = [c.cve_id for c in EpssCollector().normalize(raw).cves]
    assert ids == ["CVE-2026-1001", "CVE-2026-1002"]


def test_non_dict_page_skipped():
    raw = ["garbage", None, _page([_rec("CVE-2026-1001")], 1)]
    assert [c.cve_id for c in EpssCollector().normalize(raw).cves] == ["CVE-2026-1001"]


def test_invalid_cve_id_skipped():
    raw = [_page([_rec("CVE-1<img src=x>"), _rec("CVE-2026-1001")], 2)]
    assert [c.cve_id for c in EpssCollector().normalize(raw).cves] == ["CVE-2026-1001"]
