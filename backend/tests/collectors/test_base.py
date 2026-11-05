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


async def test_http_get_bytes_returns_bytes_and_respects_cap(respx_mock):
    from cvenom.collectors.base import ResponseTooLarge, http_get_bytes

    respx_mock.get("https://b.test/x").mock(return_value=httpx.Response(200, content=b"\x00\x01" * 8))
    assert await http_get_bytes("https://b.test/x") == b"\x00\x01" * 8
    with pytest.raises(ResponseTooLarge):
        await http_get_bytes("https://b.test/x", max_bytes=10)


async def test_http_get_conditional_304(respx_mock):
    from cvenom.collectors.base import http_get_conditional

    route = respx_mock.get("https://c.test/f").mock(
        return_value=httpx.Response(304, headers={"ETag": '"abc"'})
    )
    status, body, hdrs = await http_get_conditional(
        "https://c.test/f", etag='"abc"', last_modified="Wed, 01 Jan 2025 00:00:00 GMT"
    )
    assert (status, body) == (304, b"")
    assert hdrs["etag"] == '"abc"'
    sent = route.calls.last.request.headers
    assert sent["If-None-Match"] == '"abc"'
    assert sent["If-Modified-Since"] == "Wed, 01 Jan 2025 00:00:00 GMT"


async def test_http_get_conditional_200_returns_validators(respx_mock):
    from cvenom.collectors.base import http_get_conditional

    route = respx_mock.get("https://c.test/f").mock(
        return_value=httpx.Response(
            200, content=b"<rss/>", headers={"ETag": '"v2"', "Last-Modified": "Thu, 02 Jan 2025 00:00:00 GMT"}
        )
    )
    status, body, hdrs = await http_get_conditional("https://c.test/f")
    assert (status, body) == (200, b"<rss/>")
    assert hdrs["etag"] == '"v2"'
    assert hdrs["last-modified"] == "Thu, 02 Jan 2025 00:00:00 GMT"
    assert "If-None-Match" not in route.calls.last.request.headers
    assert "If-Modified-Since" not in route.calls.last.request.headers


async def test_http_get_conditional_too_large_not_retried(respx_mock):
    from cvenom.collectors.base import ResponseTooLarge, http_get_conditional

    route = respx_mock.get("https://c.test/f").mock(return_value=httpx.Response(200, content=b"a" * 2048))
    with pytest.raises(ResponseTooLarge):
        await http_get_conditional("https://c.test/f", max_bytes=1024)
    assert route.call_count == 1


async def test_http_get_text_aborts_past_max_bytes(respx_mock):
    from cvenom.collectors.base import ResponseTooLarge, http_get_text

    respx_mock.get("https://big.test/x").mock(return_value=httpx.Response(200, content=b"a" * 2048))
    with pytest.raises(ResponseTooLarge):
        await http_get_text("https://big.test/x", max_bytes=1024)


async def test_http_get_json_too_large_not_retried(respx_mock):
    from cvenom.collectors.base import ResponseTooLarge

    route = respx_mock.get("https://big.test/j").mock(return_value=httpx.Response(200, content=b"[" + b"1," * 2000 + b"1]"))
    with pytest.raises(ResponseTooLarge):
        await http_get_json("https://big.test/j", max_bytes=100)
    assert route.call_count == 1


def _gz(data: bytes) -> httpx.Response:
    import gzip

    return httpx.Response(
        200,
        content=gzip.compress(data),
        headers={"Content-Encoding": "gzip", "Content-Type": "text/plain; charset=utf-8"},
    )


async def test_gzip_http_get_json(respx_mock):
    respx_mock.get("https://z.test/j").mock(return_value=_gz(b'{"a": [1, 2]}'))
    assert await http_get_json("https://z.test/j") == {"a": [1, 2]}


async def test_gzip_http_get_text_respects_charset(respx_mock):
    from cvenom.collectors.base import http_get_text

    respx_mock.get("https://z.test/t").mock(return_value=_gz("café".encode()))
    assert await http_get_text("https://z.test/t") == "café"


async def test_gzip_http_get_bytes(respx_mock):
    from cvenom.collectors.base import http_get_bytes

    respx_mock.get("https://z.test/b").mock(return_value=_gz(b"\x00raw\xff"))
    assert await http_get_bytes("https://z.test/b") == b"\x00raw\xff"


async def test_gzip_http_get_conditional_200(respx_mock):
    from cvenom.collectors.base import http_get_conditional

    respx_mock.get("https://z.test/c").mock(return_value=_gz(b"<rss/>"))
    status, body, hdrs = await http_get_conditional("https://z.test/c")
    assert (status, body) == (200, b"<rss/>")
    assert "content-encoding" not in hdrs


async def test_gzip_bomb_is_capped_on_decoded_size(respx_mock):
    import gzip

    from cvenom.collectors.base import ResponseTooLarge, http_get_bytes

    bomb = gzip.compress(b"\x00" * 1_000_000)
    assert len(bomb) < 10_000
    respx_mock.get("https://z.test/bomb").mock(
        return_value=httpx.Response(200, content=bomb, headers={"Content-Encoding": "gzip"})
    )
    with pytest.raises(ResponseTooLarge):
        await http_get_bytes("https://z.test/bomb", max_bytes=10_000)


@pytest.mark.asyncio
async def test_http_get_bytes_redirects_only_when_asked(respx_mock):
    from cvenom.collectors.base import http_get_bytes

    respx_mock.get("https://r.test/a").respond(302, headers={"Location": "https://s.test/b"})
    respx_mock.get("https://s.test/b").respond(200, content=b"ok")
    with pytest.raises(httpx.HTTPStatusError):
        await http_get_bytes("https://r.test/a")
    assert await http_get_bytes("https://r.test/a", follow_redirects=True) == b"ok"
