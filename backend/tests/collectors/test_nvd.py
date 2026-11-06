import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import respx
from pydantic import SecretStr

from cvenom.collectors import base, nvd
from cvenom.collectors.nvd import NVD_URL, NvdCollector

FIXTURE = Path(__file__).parent.parent / "fixtures" / "nvd_page.json"
FMT = "%Y-%m-%dT%H:%M:%S.%f"


@pytest.fixture
def page():
    return json.loads(FIXTURE.read_text())


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    calls = []

    async def fake(delay):
        calls.append(delay)

    monkeypatch.setattr(base, "_sleep", fake)
    monkeypatch.setattr(nvd, "_sleep", fake)
    return calls


@pytest.fixture
def settings(monkeypatch):
    s = SimpleNamespace(nvd_api_key=None, backfill_days=90)
    monkeypatch.setattr(nvd, "get_settings", lambda: s)
    return s


def test_normalize_maps_fields(page, settings):
    res = NvdCollector().normalize([page])
    by_id = {c.cve_id: c for c in res.cves}
    assert set(by_id) == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}

    a = by_id["CVE-2026-1001"]
    assert a.cvss == 9.8  # Primary preferred over Secondary
    assert a.published == datetime(2026, 10, 30, 14, 15, 8, 123000, tzinfo=UTC)
    assert a.published.utcoffset() == timedelta(0)
    assert a.summary == "Heap overflow in Example Server <b>allows</b> RCE."  # raw, en

    b = by_id["CVE-2026-1002"]
    assert b.cvss == 7.5  # v3.0 fallback
    assert b.published.tzinfo is not None

    c = by_id["CVE-2026-1003"]
    assert c.cvss is None
    assert c.summary == "Unrated issue in Example Library."


def test_normalize_skips_record_missing_id(page, settings):
    page["vulnerabilities"].insert(0, {"cve": {"published": "2026-10-30T00:00:00.000"}})
    res = NvdCollector().normalize([page])
    assert len(res.cves) == 3


@respx.mock
async def test_fetch_sends_window_params_no_key(page, settings):
    route = respx.get(NVD_URL).respond(json=page)
    since = datetime(2026, 10, 21, tzinfo=UTC)
    pages = await NvdCollector().fetch(since=since)
    assert len(pages) == 1
    req = route.calls[0].request
    assert req.url.params["lastModStartDate"] == "2026-10-21T00:00:00.000"
    datetime.strptime(req.url.params["lastModEndDate"], FMT)
    assert "pubStartDate" not in req.url.params
    assert req.url.params["resultsPerPage"] == "2000"
    assert "apiKey" not in req.headers


@respx.mock
async def test_fetch_sends_api_key_header(page, settings):
    settings.nvd_api_key = SecretStr("sekret")
    route = respx.get(NVD_URL).respond(json=page)
    await NvdCollector().fetch(since=datetime.now(UTC) - timedelta(days=1))
    assert route.calls[0].request.headers["apiKey"] == "sekret"


@respx.mock
async def test_fetch_paginates_and_sleeps(page, settings, fast_sleep, monkeypatch):
    monkeypatch.setattr(nvd, "PAGE_SIZE", 2)
    vulns = page["vulnerabilities"]
    p1 = {**page, "totalResults": 3, "vulnerabilities": vulns[:2]}
    p2 = {**page, "totalResults": 3, "startIndex": 2, "vulnerabilities": vulns[2:]}
    route = respx.get(NVD_URL).mock(
        side_effect=[httpx.Response(200, json=p1), httpx.Response(200, json=p2)]
    )
    pages = await NvdCollector().fetch(since=datetime.now(UTC) - timedelta(days=1))
    assert [c.request.url.params["startIndex"] for c in route.calls] == ["0", "2"]
    assert fast_sleep == [6.0]
    assert len(NvdCollector().normalize(pages).cves) == 3


@respx.mock
async def test_fetch_sleep_shorter_with_key(page, settings, fast_sleep, monkeypatch):
    monkeypatch.setattr(nvd, "PAGE_SIZE", 2)
    settings.nvd_api_key = SecretStr("k")
    p = {**page, "totalResults": 4}
    respx.get(NVD_URL).mock(
        side_effect=[httpx.Response(200, json=p), httpx.Response(200, json=p)]
    )
    await NvdCollector().fetch(since=datetime.now(UTC) - timedelta(days=1))
    assert fast_sleep == [0.6]


@respx.mock
async def test_fetch_splits_window_over_120_days(page, settings):
    empty = {**page, "totalResults": 0, "vulnerabilities": []}
    route = respx.get(NVD_URL).respond(json=empty)
    await NvdCollector().fetch(since=datetime.now(UTC) - timedelta(days=300))
    assert len(route.calls) == 3
    prev_end = None
    for call in route.calls:
        p = call.request.url.params
        start = datetime.strptime(p["lastModStartDate"], FMT)
        end = datetime.strptime(p["lastModEndDate"], FMT)
        assert end - start <= timedelta(days=120)
        if prev_end is not None:
            assert start >= prev_end
        prev_end = end


@respx.mock
async def test_default_since_uses_backfill_days(page, settings):
    settings.backfill_days = 10
    route = respx.get(NVD_URL).respond(json=page)
    await NvdCollector().fetch()
    p = route.calls[0].request.url.params
    start = datetime.strptime(p["lastModStartDate"], FMT)
    end = datetime.strptime(p["lastModEndDate"], FMT)
    assert timedelta(days=9, hours=23) < end - start < timedelta(days=10, minutes=1)


def test_registered():
    assert base.REGISTRY["nvd"] is NvdCollector
    assert NvdCollector.cadence_seconds == 7200


@respx.mock
async def test_fetch_honors_self_since(page, settings):
    route = respx.get(NVD_URL).respond(json=page)
    since = datetime.now(UTC) - timedelta(days=2)
    await NvdCollector(since=since).fetch()
    p = route.calls[0].request.url.params
    start = datetime.strptime(p["lastModStartDate"], FMT)
    end = datetime.strptime(p["lastModEndDate"], FMT)
    assert timedelta(days=1, hours=23) < end - start < timedelta(days=2, minutes=1)


# --- poison records must not fail the run (#8) ---


@pytest.mark.parametrize("poison", ["garbage", None, 5, ["x"], {"cve": "not-a-dict"}, {"cve": {"id": 7}}])
def test_non_dict_or_malformed_record_skipped_others_kept(page, settings, poison, caplog):
    page["vulnerabilities"].insert(1, poison)
    with caplog.at_level("WARNING"):
        res = NvdCollector().normalize([page])
    assert {c.cve_id for c in res.cves} == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}


def test_non_dict_page_skipped(page, settings):
    res = NvdCollector().normalize(["garbage", None, page])
    assert len(res.cves) == 3


def test_invalid_cve_id_skipped(page, settings):
    page["vulnerabilities"][0]["cve"]["id"] = "CVE-1<img src=x>"
    res = NvdCollector().normalize([page])
    assert {c.cve_id for c in res.cves} == {"CVE-2026-1002", "CVE-2026-1003"}


# --- detail fields (radar refinements, spec D) ---


def _metric(vec, sev, score, typ):
    return {"type": typ, "cvssData": {"baseScore": score, "vectorString": vec, "baseSeverity": sev}}


def test_nvd_maps_vector_severity_cwes_refs_last_modified(settings):
    rec = {"vulnerabilities": [{"cve": {
        "id": "CVE-2026-2001",
        "published": "2026-11-01T00:00:00.000",
        "lastModified": "2026-11-03T12:30:00.000",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV31": [
            _metric("CVSS:3.1/SECONDARY", "LOW", 2.0, "Secondary"),
            _metric("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", 9.8, "Primary"),
        ]},
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-79"}]},
            {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
        ],
        "references": (
            [{"url": f"https://example.com/{i}", "tags": ["Vendor Advisory"]} for i in range(24)]
            + [{"url": "http://abc.onion/x", "tags": []}]
        ),
    }}]}
    c = NvdCollector().normalize([rec]).cves[0]
    assert c.cvss == 9.8
    assert c.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert c.cvss_severity == "CRITICAL"
    assert c.cwes == ["CWE-79"]
    assert len(c.references) == 20
    assert not any("onion" in r.url for r in c.references)
    assert c.references[0].tags == ["Vendor Advisory"]
    assert c.last_modified == datetime(2026, 11, 3, 12, 30, tzinfo=UTC)


def test_nvd_record_without_metrics_or_weaknesses(settings):
    rec = {"vulnerabilities": [{"cve": {"id": "CVE-2026-2002", "descriptions": []}}]}
    res = NvdCollector().normalize([rec])
    assert len(res.cves) == 1
    c = res.cves[0]
    assert c.cvss is None and c.cvss_vector is None and c.cvss_severity is None
    assert c.cwes is None and c.references is None and c.last_modified is None


@pytest.mark.parametrize("bad", ["not-a-date", 12, ["x"], {"a": 1}])
def test_nvd_bad_last_modified_keeps_record(settings, bad):
    rec = {"vulnerabilities": [{"cve": {"id": "CVE-2026-2003", "lastModified": bad}}]}
    res = NvdCollector().normalize([rec])
    assert len(res.cves) == 1 and res.cves[0].last_modified is None


@pytest.mark.parametrize(
    "cve_extra",
    [
        {"weaknesses": ["x", None, 5]},
        {"weaknesses": [{"description": "CWE-79"}, {"description": [None, "x", 3]}]},
        {"weaknesses": 5},
        {"weaknesses": "CWE-79"},
        {"references": ["x", None, 5]},
        {"references": 5},
        {"references": "http://x"},
    ],
)
def test_nvd_malformed_detail_shapes_keep_record(settings, cve_extra):
    rec = {"vulnerabilities": [{"cve": {"id": "CVE-2026-2004", **cve_extra}}]}
    res = NvdCollector().normalize([rec])
    assert len(res.cves) == 1
    assert res.cves[0].cwes is None and res.cves[0].references is None
