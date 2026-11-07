import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import select

from cvenom.collectors import base
from cvenom.collectors.base import REGISTRY, CollectorResult
from cvenom.collectors.metasploit import MODULES_URL, MetasploitCollector
from cvenom.models import Cve, CveEvent, Story
from cvenom.pipeline import ingest
from cvenom.schemas import NormalizedCve

FIX = Path(__file__).parent.parent / "fixtures"


def _raw() -> bytes:
    return (FIX / "metasploit_modules.json").read_bytes()


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    async def fake(delay):
        pass

    monkeypatch.setattr(base, "_sleep", fake)


def _by_cve(res):
    return {e.cve_id: e for e in res.cve_events}


def test_modules_become_poc_events_one_per_cve():
    res = MetasploitCollector().normalize(_raw())
    assert res.stories == []
    assert all(c.poc_badge for c in res.cves)
    assert {c.cve_id for c in res.cves} == {e.cve_id for e in res.cve_events}
    assert len(res.cve_events) == len({e.cve_id for e in res.cve_events})
    ev = _by_cve(res)["CVE-2021-44228"]  # the auxiliary scanner for it is ignored
    assert (ev.kind, ev.source) == ("poc_published", "Metasploit")
    assert ev.occurred_at == datetime(2021, 12, 9, tzinfo=UTC)
    assert ev.detail == {
        "module": "exploit/multi/http/log4shell_header_injection",
        "rank": 600,
        "path": "/modules/exploits/multi/http/log4shell_header_injection.rb",
        "url": "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/exploits/multi/http/log4shell_header_injection.rb",
    }


def test_multiple_cves_and_multiple_modules_per_cve():
    by = _by_cve(MetasploitCollector().normalize(_raw()))
    assert "CVE-2021-45046" in by
    # two exploit modules name CVE-2017-0144: first by name wins, count recorded
    ev = by["CVE-2017-0144"]
    assert ev.detail["module"] == "exploit/windows/smb/ms17_010_eternalblue"
    assert ev.detail["module_count"] == 2
    assert by["CVE-2017-0143"].detail["module"] == "exploit/windows/smb/ms17_010_psexec"
    assert "module_count" not in by["CVE-2017-0143"].detail


def test_non_exploit_non_cve_and_malformed_are_skipped():
    res = MetasploitCollector().normalize(_raw())
    ids = {c.cve_id for c in res.cves}
    assert "CVE-2020-1111" not in ids  # post module
    assert "CVE-2020-0001" not in ids  # malformed record
    # weird refs: valid id kept once (case-insensitive), junk dropped, bad date falls back to mod_time
    ev = _by_cve(res)["CVE-2020-5555"]
    assert ev.occurred_at == datetime(2023, 3, 4, 5, 6, 7, tzinfo=UTC)
    assert not any(i.startswith("CVE-20-") for i in ids)
    assert len(ids) == 6  # 44228, 45046, 0144, 0143, 76461, 5555


def test_future_date_is_capped():
    ev = _by_cve(MetasploitCollector().normalize(_raw()))["CVE-2026-76461"]
    assert datetime.now(UTC) - timedelta(minutes=5) <= ev.occurred_at
    assert ev.occurred_at <= datetime.now(UTC) + timedelta(minutes=1)


def test_text_is_not_trusted_and_bad_input_is_safe():
    c = MetasploitCollector()
    assert c.normalize(None).cve_events == []
    assert c.normalize(b"").cve_events == []
    assert c.normalize(b"not json").cve_events == []
    assert c.normalize(b"[1,2]").cve_events == []
    evil = {
        "a": {
            "fullname": "exploit/x/y<script>alert(1)</script>", "type": "exploit", "rank": 1,
            "references": ["CVE-2024-1234"], "disclosure_date": "2024-01-01",
            "path": "/modules/exploits/x/y.rb",
        },
        "b": {
            "fullname": "exploit/x/ok", "type": "exploit", "rank": 1,
            "references": ["CVE-2024-4321"], "disclosure_date": "2024-01-01",
            "path": "/modules/../../evil path.rb",
        },
    }
    res = c.normalize(json.dumps(evil).encode())
    (ev,) = res.cve_events  # unsafe fullname skipped; unsafe path replaced by one derived from it
    assert ev.cve_id == "CVE-2024-4321"
    assert ev.detail["url"] == (
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/x/ok.rb"
    )


def test_registered_enrich_only_daily():
    assert REGISTRY["metasploit"] is MetasploitCollector
    assert MetasploitCollector.enrich_only is True
    assert MetasploitCollector.cadence_seconds == 86400


@respx.mock
async def test_fetch_fixed_url_conditional_and_state():
    route = respx.get(MODULES_URL).mock(
        return_value=httpx.Response(200, content=_raw(), headers={"ETag": '"abc"'})
    )
    c = MetasploitCollector()
    res = await c.run()
    assert c.last_error is None and res.cve_events
    assert route.calls[0].request.headers["user-agent"] == base.USER_AGENT
    assert c.state["etag"] == '"abc"'

    route.mock(return_value=httpx.Response(304))
    c2 = MetasploitCollector(state={"etag": '"abc"', "cve_count": 5, "last_cve_count": 5})
    res2 = await c2.run()
    assert c2.last_error is None and res2.cve_events == []
    assert route.calls.last.request.headers["if-none-match"] == '"abc"'


@respx.mock
async def test_new_cve_rows_bypass_validators():
    route = respx.get(MODULES_URL).mock(return_value=httpx.Response(200, content=_raw()))
    c = MetasploitCollector(state={"etag": '"abc"', "cve_count": 6, "last_cve_count": 5})
    await c.run()
    assert "if-none-match" not in route.calls[0].request.headers
    assert c.state["last_cve_count"] == 6


@pytest.mark.parametrize("code", [408, 429, 500, 503])
@respx.mock
async def test_transient_errors_fail_the_run(code):
    respx.get(MODULES_URL).mock(return_value=httpx.Response(code))
    c = MetasploitCollector(state={"etag": '"abc"'})
    res = await c.run()
    assert res.cve_events == [] and isinstance(c.last_error, httpx.HTTPStatusError)
    assert c.state["etag"] == '"abc"'


def test_end_to_end_poc_badge_filter_and_idempotent(db_session):
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2021-44228")]))
    res = MetasploitCollector().normalize(_raw())
    assert db_session.get(Cve, "CVE-2021-44228").poc_badge is False
    ingest(db_session, res, enrich_only=True, collector="metasploit")
    assert db_session.get(Cve, "CVE-2021-45046") is None  # enrich-only: never stub-creates
    assert db_session.get(Cve, "CVE-2021-44228").poc_badge is True
    q = select(CveEvent).where(CveEvent.kind == "poc_published")
    rows = db_session.scalars(q).all()
    assert [(r.cve_id, r.source) for r in rows] == [("CVE-2021-44228", "Metasploit")]
    ingest(db_session, MetasploitCollector().normalize(_raw()), enrich_only=True,
           collector="metasploit")
    assert len(db_session.scalars(q).all()) == 1
    assert db_session.scalars(select(Story)).all() == []
