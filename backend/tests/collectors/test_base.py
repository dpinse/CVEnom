import httpx
import pytest

from cvenom.collectors import base
from cvenom.collectors.base import Collector, CollectorResult, http_get_json


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    calls = []

    async def fake(delay):
        calls.append(delay)

    monkeypatch.setattr(base, "_sleep", fake)
    return calls


@pytest.mark.asyncio
async def test_run_returns_empty_on_fetch_failure(monkeypatch):
    class Boom(Collector):
        name = "boom"
        cadence_seconds = 60

        async def fetch(self):
            raise TimeoutError()

        def normalize(self, raw):
            return CollectorResult(cves=[object()])

    res = await Boom().run()
    assert res.cves == [] and res.stories == []


@pytest.mark.asyncio
async def test_run_returns_empty_on_normalize_failure():
    class Bad(Collector):
        name = "bad"
        cadence_seconds = 60

        async def fetch(self):
            return {}

        def normalize(self, raw):
            raise ValueError("malformed")

    res = await Bad().run()
    assert res.cves == [] and res.stories == [] and res.events == []


@pytest.mark.asyncio
async def test_run_returns_normalized_result():
    class Ok(Collector):
        name = "ok"
        cadence_seconds = 60

        async def fetch(self):
            return 1

        def normalize(self, raw):
            return CollectorResult(events=[{"n": raw}])

    assert (await Ok().run()).events == [{"n": 1}]


def test_result_defaults_not_shared():
    a, b = CollectorResult(), CollectorResult()
    a.cves.append(1)
    assert b.cves == []


@pytest.mark.asyncio
async def test_http_get_json_retries_then_succeeds(respx_mock):
    route = respx_mock.get("https://api.test/x")
    route.side_effect = [httpx.Response(503), httpx.Response(200, json={"ok": True})]
    assert await http_get_json("https://api.test/x", retries=3) == {"ok": True}


@pytest.mark.asyncio
async def test_http_get_json_does_not_retry_404(respx_mock):
    route = respx_mock.get("https://api.test/x").mock(return_value=httpx.Response(404))
    with pytest.raises(httpx.HTTPStatusError):
        await http_get_json("https://api.test/x", retries=3)
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_http_get_json_raises_when_retries_exhausted(respx_mock):
    route = respx_mock.get("https://api.test/x").mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        await http_get_json("https://api.test/x", retries=3)
    assert route.call_count == 3


@pytest.mark.asyncio
async def test_http_get_json_retries_timeouts(respx_mock):
    route = respx_mock.get("https://api.test/x")
    route.side_effect = [httpx.ConnectTimeout("t"), httpx.Response(200, json=[1])]
    assert await http_get_json("https://api.test/x") == [1]


@pytest.mark.asyncio
async def test_http_get_json_honors_retry_after_capped(respx_mock, fast_sleep):
    route = respx_mock.get("https://api.test/x")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "9999"}),
        httpx.Response(200, json={}),
    ]
    await http_get_json("https://api.test/x")
    assert fast_sleep == [base.MAX_RETRY_AFTER]


@pytest.mark.asyncio
async def test_http_get_json_sends_generic_user_agent(respx_mock):
    route = respx_mock.get("https://api.test/x").mock(
        return_value=httpx.Response(200, json={})
    )
    await http_get_json("https://api.test/x")
    ua = route.calls[0].request.headers["user-agent"]
    assert ua.startswith("CVEnom/") and "@" not in ua


def test_register_adds_and_rejects_duplicates():
    from cvenom.collectors.base import REGISTRY, register

    @register
    class Reg(Collector):
        name = "reg-test"
        cadence_seconds = 1

        async def fetch(self):
            return None

        def normalize(self, raw):
            return CollectorResult()

    try:
        assert REGISTRY["reg-test"] is Reg
        with pytest.raises(ValueError):
            register(Reg)
    finally:
        REGISTRY.pop("reg-test", None)
