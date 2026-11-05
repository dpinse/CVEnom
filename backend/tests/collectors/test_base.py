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


def test_collector_init_stores_since_and_copies_state():
    class C(Collector):
        name = "c"
        cadence_seconds = 1

        async def fetch(self):
            return None

        def normalize(self, raw):
            return CollectorResult()

    state = {"seen": ["a"]}
    c = C(since=None, state=state)
    assert c.since is None
    assert c.state == state and c.state is not state
    c.state["seen"] = ["b"]
    assert state == {"seen": ["a"]}
    assert C().state == {}


def test_collector_init_deep_copies_nested_state():
    class C(Collector):
        name = "c2"
        cadence_seconds = 1

        async def fetch(self):
            return None

        def normalize(self, raw):
            return CollectorResult()

    state = {"seen": ["a"]}
    c = C(state=state)
    state["seen"].append("z")
    assert c.state == {"seen": ["a"]}


@pytest.mark.asyncio
async def test_http_get_text_returns_body(respx_mock):
    respx_mock.get("https://api.test/t").mock(return_value=httpx.Response(200, text="a,b\nc,d\n"))
    assert await base.http_get_text("https://api.test/t") == "a,b\nc,d\n"


@pytest.mark.asyncio
async def test_http_get_text_retries_then_succeeds_with_user_agent(respx_mock):
    route = respx_mock.get("https://api.test/t")
    route.side_effect = [httpx.Response(503), httpx.Response(200, text="ok")]
    assert await base.http_get_text("https://api.test/t") == "ok"
    assert route.call_count == 2
    assert route.calls[0].request.headers["user-agent"].startswith("CVEnom/")


@pytest.mark.asyncio
async def test_http_get_text_raises_when_retries_exhausted(respx_mock):
    route = respx_mock.get("https://api.test/t").mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        await base.http_get_text("https://api.test/t", retries=2)
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_run_records_last_error_and_clears_on_success():
    class Flaky(Collector):
        name = "flaky"
        cadence_seconds = 60
        fail = True

        async def fetch(self):
            if self.fail:
                raise TimeoutError("down")
            return {}

        def normalize(self, raw):
            return CollectorResult()

    c = Flaky()
    assert c.last_error is None
    await c.run()
    assert isinstance(c.last_error, TimeoutError)
    c.fail = False
    await c.run()
    assert c.last_error is None



@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "-inf", "Infinity"])
@pytest.mark.asyncio
async def test_non_finite_retry_after_falls_back_to_backoff(respx_mock, fast_sleep, value):
    route = respx_mock.get("https://api.test/x")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": value}),
        httpx.Response(200, json={}),
    ]
    await http_get_json("https://api.test/x")
    assert fast_sleep == [base.BACKOFF_BASE]
