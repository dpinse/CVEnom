import logging
from datetime import UTC, datetime

import httpx
import pytest

from cvenom.collectors import base, osv
from cvenom.collectors.base import REGISTRY
from cvenom.collectors.osv import INDEX_URL, VULN_URL, OsvCollector

SINCE = datetime(2026, 11, 1, tzinfo=UTC)

INDEX = """\
2026-11-04T10:00:00Z,GHSA/GHSA-aaaa-bbbb-cccc
2026-11-04T09:00:00Z,Debian:11/DSA-1234
this line is garbage
2026-11-03T09:00:00Z,PyPI/PYSEC-2026-1
2026-11-02T09:00:00Z,GHSA/GHSA-aaaa-bbbb-cccc
2026-11-01T00:00:00Z,Go/GO-2026-1
2026-10-31T23:59:59Z,Go/GO-OLD-1
2026-10-30T00:00:00Z,Go/GO-OLDER-2
"""

FIXED = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2026-1001", "CVE-2026-1002", "PYSEC-2026-9"],
    "summary": "osv summary",
    "published": "2026-11-01T00:00:00Z",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "foo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
        },
        {"package": {"ecosystem": "npm", "name": "foo-js"}, "ranges": []},
    ],
}
UNFIXED = {
    "id": "GHSA-dddd-eeee-ffff",
    "aliases": ["CVE-2026-2001"],
    "affected": [
        {
            "package": {"ecosystem": "Go", "name": "example.com/x"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }
    ],
}
NO_CVE = {"id": "GHSA-gggg-hhhh-iiii", "aliases": ["PYSEC-1"], "affected": []}
OWN_CVE = {"id": "CVE-2026-3001", "affected": [{"package": {"ecosystem": "npm", "name": "bar"}}]}


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    calls = []

    async def fake(delay):
        calls.append(delay)

    monkeypatch.setattr(base, "_sleep", fake)
    return calls


def test_parse_index_stops_at_since_and_takes_id_after_last_slash():
    ids = osv.parse_index(INDEX, SINCE)
    assert ids == [
        "GHSA-aaaa-bbbb-cccc",
        "DSA-1234",
        "PYSEC-2026-1",
        "GO-2026-1",
    ]


def test_parse_index_multi_slash_takes_last_segment():
    text = "2026-11-04T10:00:00Z,Ubuntu/22.04/USN-1\n2026-11-04T09:00:00Z,Foo/bar/GHSA-x\n"
    assert osv.parse_index(text, SINCE) == ["USN-1", "GHSA-x"]


def test_parse_index_warns_with_malformed_count(caplog):
    # Only the bad-timestamp line is malformed; it precedes the cutoff.
    text = "nope,Go/X\n2026-11-04T10:00:00Z,Go/GO-1\n2026-10-01T00:00:00Z,Go/GO-OLD\n"
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.osv"):
        osv.parse_index(text, SINCE)
    msgs = [r.getMessage() for r in caplog.records if "malformed" in r.getMessage()]
    assert msgs == ["osv: skipped 1 malformed index line(s)"]


def test_parse_index_cap_warns(monkeypatch, caplog):
    monkeypatch.setattr(osv, "MAX_IDS", 2)
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.osv"):
        ids = osv.parse_index(INDEX, SINCE)
    assert ids == ["GHSA-aaaa-bbbb-cccc", "DSA-1234"]
    assert any("cap" in r.message.lower() for r in caplog.records)


def test_parse_index_no_warning_when_not_capped(caplog):
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.osv"):
        osv.parse_index(INDEX, SINCE)
    assert not [r for r in caplog.records if "cap" in r.message.lower()]


def test_patch_available_true_and_false():
    res = OsvCollector().normalize([FIXED, UNFIXED])
    by_id = {c.cve_id: c for c in res.cves}
    assert by_id["CVE-2026-1001"].patch_available is True
    assert by_id["CVE-2026-2001"].patch_available is False


def test_aliases_expand_and_no_cve_skipped_and_own_cve_included():
    res = OsvCollector().normalize([FIXED, NO_CVE, OWN_CVE])
    assert sorted(c.cve_id for c in res.cves) == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-3001"]
    own = next(c for c in res.cves if c.cve_id == "CVE-2026-3001")
    assert own.patch_available is False


def test_affected_formatting_and_no_canonical_fields():
    res = OsvCollector().normalize([FIXED])
    for c in res.cves:
        assert c.affected == ["PyPI:foo", "npm:foo-js"]
        assert c.summary is None
        assert c.published is None
        assert c.kev is False
        assert c.cvss is None


def test_normalize_skips_malformed_record(caplog):
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.osv"):
        res = OsvCollector().normalize([{"id": "CVE-2026-0001", "affected": "nope"}, OWN_CVE])
    assert [c.cve_id for c in res.cves] == ["CVE-2026-3001"]
    assert any("skipping malformed record CVE-2026-0001" in r.getMessage() for r in caplog.records)


def test_enrich_only_and_registration():
    assert OsvCollector.enrich_only is True
    assert REGISTRY["osv"] is OsvCollector
    assert OsvCollector.name == "osv"
    assert OsvCollector.cadence_seconds == 7200


@pytest.mark.asyncio
async def test_fetch_skips_failed_vuln_and_continues(respx_mock, fast_sleep, caplog):
    # 1 failure out of 5 fetches (20%) is at the threshold: logged, run continues.
    index = INDEX.replace(
        "2026-11-01T00:00:00Z,Go/GO-2026-1\n",
        "2026-11-01T00:00:00Z,Go/GO-2026-1\n2026-11-01T00:00:00Z,Go/GO-2026-2\n",
    )
    respx_mock.get(INDEX_URL).mock(return_value=httpx.Response(200, text=index))
    respx_mock.get(VULN_URL.format(id="GO-2026-2")).mock(return_value=httpx.Response(200, json=NO_CVE))
    respx_mock.get(VULN_URL.format(id="GHSA-aaaa-bbbb-cccc")).mock(
        return_value=httpx.Response(200, json=FIXED)
    )
    respx_mock.get(VULN_URL.format(id="DSA-1234")).mock(return_value=httpx.Response(500))
    respx_mock.get(VULN_URL.format(id="PYSEC-2026-1")).mock(
        return_value=httpx.Response(200, json=UNFIXED)
    )
    respx_mock.get(VULN_URL.format(id="GO-2026-1")).mock(
        return_value=httpx.Response(200, json=OWN_CVE)
    )
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.osv"):
        raw = await OsvCollector().fetch(since=SINCE)
    assert [r["id"] for r in raw] == [
        "GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "CVE-2026-3001", "GHSA-gggg-hhhh-iiii"
    ]
    assert any("DSA-1234" in r.getMessage() for r in caplog.records)
    assert osv.REQUEST_DELAY in fast_sleep


@pytest.mark.asyncio
async def test_fetch_defaults_since_to_seven_days(respx_mock):
    recent = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = f"{recent},Go/GO-NEW-1\n2000-01-01T00:00:00Z,Go/GO-ANCIENT-1\n"
    respx_mock.get(INDEX_URL).mock(return_value=httpx.Response(200, text=text))
    route = respx_mock.get(VULN_URL.format(id="GO-NEW-1")).mock(
        return_value=httpx.Response(200, json=OWN_CVE)
    )
    raw = await OsvCollector().fetch()
    assert len(raw) == 1 and route.call_count == 1


@pytest.mark.asyncio
async def test_fetch_uses_self_since(respx_mock):
    text = "2026-11-04T10:00:00Z,Go/GO-A-1\n2026-11-02T00:00:00Z,Go/GO-B-1\n"
    respx_mock.get(INDEX_URL).mock(return_value=httpx.Response(200, text=text))
    a = respx_mock.get(VULN_URL.format(id="GO-A-1")).mock(return_value=httpx.Response(200, json=OWN_CVE))
    b = respx_mock.get(VULN_URL.format(id="GO-B-1")).mock(return_value=httpx.Response(200, json=OWN_CVE))
    await OsvCollector(since=datetime(2026, 11, 3, tzinfo=UTC)).fetch()
    assert a.call_count == 1 and b.call_count == 0


# --- per-CVE aggregation across records (#4) ---

FIXED_SAME_CVE = {
    "id": "PYSEC-2026-50",
    "aliases": ["CVE-2026-5050"],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "fixedpkg"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
        }
    ],
}
UNFIXED_SAME_CVE = {
    "id": "GHSA-5050-5050-5050",
    "aliases": ["CVE-2026-5050"],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "openpkg"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }
    ],
}


@pytest.mark.parametrize("order", ["fixed_first", "unfixed_first"])
def test_records_for_same_cve_aggregate_patch_any_and_affected_union(order):
    recs = [FIXED_SAME_CVE, UNFIXED_SAME_CVE]
    if order == "unfixed_first":
        recs.reverse()
    res = OsvCollector().normalize(recs)
    assert [c.cve_id for c in res.cves] == ["CVE-2026-5050"]  # one NormalizedCve per CVE
    c = res.cves[0]
    assert c.patch_available is True
    assert sorted(c.affected) == ["PyPI:fixedpkg", "npm:openpkg"]


def test_non_dict_event_containing_fixed_substring_is_not_a_fix():
    rec = {
        "id": "GHSA-6060-6060-6060",
        "aliases": ["CVE-2026-6060"],
        "affected": [
            {"package": {"ecosystem": "Go", "name": "x"}, "ranges": [{"events": ["unfixed", None, 3]}]}
        ],
    }
    res = OsvCollector().normalize([rec])
    assert [(c.cve_id, c.patch_available) for c in res.cves] == [("CVE-2026-6060", False)]


def test_invalid_alias_skipped_but_valid_aliases_kept(caplog):
    rec = dict(FIXED_SAME_CVE, aliases=["CVE-1<img src=x>", "cve-2026-5050", "CVE-24-1"])
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.osv"):
        res = OsvCollector().normalize([rec])
    assert [c.cve_id for c in res.cves] == ["CVE-2026-5050"]
    assert any("CVE-1<img src=x>" in r.getMessage() for r in caplog.records)



# --- failure threshold and id validation (#9b, #9c) ---


def _index(*ids):
    return "".join(f"2026-11-04T10:00:00Z,Go/{i}\n" for i in ids)


@pytest.mark.asyncio
async def test_fetch_raises_when_more_than_20_percent_fail(respx_mock):
    ids = [f"GO-2026-{n}" for n in range(1, 6)]
    respx_mock.get(INDEX_URL).mock(return_value=httpx.Response(200, text=_index(*ids)))
    for i in ids[:3]:
        respx_mock.get(VULN_URL.format(id=i)).mock(return_value=httpx.Response(200, json=OWN_CVE))
    for i in ids[3:]:  # 2 of 5 = 40% fail
        respx_mock.get(VULN_URL.format(id=i)).mock(return_value=httpx.Response(404))
    with pytest.raises(RuntimeError, match="2/5"):
        await OsvCollector(since=SINCE).fetch()


@pytest.mark.asyncio
async def test_run_marked_failed_when_threshold_exceeded(respx_mock):
    respx_mock.get(INDEX_URL).mock(return_value=httpx.Response(200, text=_index("GO-2026-1")))
    respx_mock.get(VULN_URL.format(id="GO-2026-1")).mock(return_value=httpx.Response(404))
    c = OsvCollector(since=SINCE)
    res = await c.run()
    assert c.last_error is not None and res.cves == []


@pytest.mark.asyncio
async def test_invalid_ids_skipped_with_warning_and_valid_ids_quoted(respx_mock, caplog):
    bad = ["..", "GO?x=1", "GO#frag", "GO%2F..", "GO 1", "GO\\x"]
    good = "GHSA:abc_1.2-x"
    text = _index(*bad) + _index(good)
    respx_mock.get(INDEX_URL).mock(return_value=httpx.Response(200, text=text))
    route = respx_mock.get(url__startswith="https://api.osv.dev/v1/vulns/").mock(
        return_value=httpx.Response(200, json=OWN_CVE)
    )
    with caplog.at_level(logging.WARNING, logger="cvenom.collectors.osv"):
        raw = await OsvCollector(since=SINCE).fetch()
    assert route.call_count == 1
    assert route.calls[0].request.url.raw_path == b"/v1/vulns/GHSA%3Aabc_1.2-x"
    assert len(raw) == 1
    invalid_msgs = [r.getMessage() for r in caplog.records if "invalid" in r.getMessage()]
    assert len(invalid_msgs) == len(bad)
