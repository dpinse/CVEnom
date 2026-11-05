import base64
import logging
import os
from contextlib import contextmanager

import fakeredis
import httpx
import pytest
from fastapi import Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from redis.exceptions import ConnectionError as RedisConnectionError

from cvenom.api import create_app
from cvenom.api import ratelimit as rl
from cvenom.api.ratelimit import RateLimiter, enforce_login_limits, rate_limit
from cvenom.config import get_settings

from test_app import make_user, token_for


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    rl._last_warn.clear()
    yield
    get_settings.cache_clear()


class DownRedis:
    """Every command raises, like an unreachable server."""

    async def eval(self, *a, **k):
        raise RedisConnectionError("down")

    async def get(self, *a, **k):
        raise RedisConnectionError("down")

    async def set(self, *a, **k):
        raise RedisConnectionError("down")


class SetFailsRedis:
    def __init__(self, inner):
        self.inner = inner

    async def get(self, *a, **k):
        return await self.inner.get(*a, **k)

    async def set(self, *a, **k):
        raise RedisConnectionError("down")


def make_app(db_session, redis, cache_paths=(), **overrides):
    settings = get_settings().model_copy(update=overrides)

    @contextmanager
    def factory():
        yield db_session

    app = create_app(settings, redis=redis, session_factory=factory, cache_paths=cache_paths)
    calls = {"n": 0}

    @app.get("/t/read", dependencies=[Depends(rate_limit("read"))])
    def read():
        return {"ok": True}

    @app.get("/t/auth", dependencies=[Depends(rate_limit("auth"))])
    def auth():
        return {"ok": True}

    @app.post("/t/login")
    async def login(request: Request, body: dict):
        await enforce_login_limits(request, body["email"])
        return {"ok": True}

    @app.get("/pub/json")
    def pub_json():
        calls["n"] += 1
        return {"n": calls["n"]}

    @app.get("/pub/missing")
    def pub_missing():
        calls["n"] += 1
        return JSONResponse({"error": "nope"}, status_code=404)

    @app.get("/pub/text")
    def pub_text():
        calls["n"] += 1
        return PlainTextResponse("hello")

    @app.get("/pub/cookie")
    def pub_cookie():
        calls["n"] += 1
        r = JSONResponse({"n": calls["n"]})
        r.set_cookie("sid", "x")
        return r

    @app.get("/other/json")
    def other_json():
        calls["n"] += 1
        return {"n": calls["n"]}

    app.state.calls = calls
    return app


def client(app, peer=("1.2.3.4", 1234)):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=peer), base_url="http://test"
    )


@pytest.fixture
def redis():
    return fakeredis.FakeAsyncRedis()


# ---------------------------------------------------------------- limiter


async def test_hit_counts_and_ttl(redis):
    lim = RateLimiter(redis)
    assert await lim.hit("k", 2, 30) == (True, 30)
    assert (await lim.hit("k", 2, 30))[0] is True
    allowed, retry = await lim.hit("k", 2, 30)
    assert allowed is False and 0 < retry <= 30


async def test_hit_window_resets(redis):
    lim = RateLimiter(redis)
    for _ in range(3):
        await lim.hit("k", 1, 30)
    assert (await lim.hit("k", 1, 30))[0] is False
    await redis.delete("k")  # TTL expiry
    assert await lim.hit("k", 1, 30) == (True, 30)


async def test_61st_anonymous_read_is_429_then_resets(db_session, redis):
    app = make_app(db_session, redis)
    async with client(app) as c:
        for _ in range(60):
            assert (await c.get("/t/read")).status_code == 200
        r = await c.get("/t/read")
        assert r.status_code == 429
        assert r.json() == {"error": "rate_limited"}
        assert 0 < int(r.headers["retry-after"]) <= 60
        keys = [k async for k in redis.scan_iter("cvenom:rl:read:ip:*")]
        assert keys == [b"cvenom:rl:read:ip:1.2.3.4"]
        await redis.delete(*keys)  # window elapsed
        assert (await c.get("/t/read")).status_code == 200


async def test_separate_ips_have_separate_buckets(db_session, redis):
    app = make_app(db_session, redis, rate_anon_per_min=2)
    async with client(app, ("1.1.1.1", 1)) as a, client(app, ("2.2.2.2", 1)) as b:
        assert (await a.get("/t/read")).status_code == 200
        assert (await a.get("/t/read")).status_code == 200
        assert (await a.get("/t/read")).status_code == 429
        assert (await b.get("/t/read")).status_code == 200


async def test_authed_user_keyed_by_user_id_not_ip(db_session, redis):
    app = make_app(db_session, redis, rate_authed_per_min=2, rate_anon_per_min=1)
    user = make_user(db_session)
    tok, _ = token_for(db_session, user)
    h = {"Authorization": f"Bearer {tok}"}
    async with client(app, ("1.1.1.1", 1)) as a, client(app, ("2.2.2.2", 1)) as b:
        assert (await a.get("/t/read", headers=h)).status_code == 200
        assert (await b.get("/t/read", headers=h)).status_code == 200  # other IP, same user
        r = await a.get("/t/read", headers=h)
        assert r.status_code == 429 and "retry-after" in r.headers
    assert await redis.get(f"cvenom:rl:read:u:{user.id}") is not None
    assert [k async for k in redis.scan_iter("cvenom:rl:read:ip:*")] == []


# ------------------------------------------------------------------ login


async def test_login_limited_per_ip(db_session, redis):
    app = make_app(db_session, redis, rate_login_per_15min_ip=3)
    async with client(app) as c:
        for i in range(3):
            assert (await c.post("/t/login", json={"email": f"u{i}@x.com"})).status_code == 200
        r = await c.post("/t/login", json={"email": "u9@x.com"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


async def test_login_limited_by_email_when_ip_rotates(db_session, redis):
    app = make_app(db_session, redis, rate_login_per_15min_email=3)
    for i in range(3):
        async with client(app, (f"9.9.9.{i}", 1)) as c:
            r = await c.post("/t/login", json={"email": "Victim@Example.com"})
            assert r.status_code == 200
    async with client(app, ("9.9.9.99", 1)) as c:
        r = await c.post("/t/login", json={"email": "  victim@example.COM "})
        other = await c.post("/t/login", json={"email": "someone@else.com"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    assert other.status_code == 200
    keys = [k.decode() async for k in redis.scan_iter("cvenom:rl:login:*")]
    assert not any("example" in k.lower() for k in keys)  # no PII in keys


# ------------------------------------------------------------ redis down


async def test_login_fails_closed_when_redis_down(db_session):
    app = make_app(db_session, DownRedis())
    async with client(app) as c:
        r = await c.post("/t/login", json={"email": "a@b.com"})
    assert r.status_code == 503 and r.json() == {"error": "unavailable"}


async def test_auth_scope_fails_closed_when_redis_down(db_session):
    app = make_app(db_session, DownRedis())
    async with client(app) as c:
        r = await c.get("/t/auth")
    assert r.status_code == 503 and r.json() == {"error": "unavailable"}


async def test_reads_fail_open_with_rate_limited_warning(db_session, caplog):
    app = make_app(db_session, DownRedis())
    with caplog.at_level(logging.WARNING, logger="cvenom.api.ratelimit"):
        async with client(app) as c:
            for _ in range(5):
                assert (await c.get("/t/read")).status_code == 200
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1


async def test_warning_logged_again_after_interval(monkeypatch, caplog):
    t = [1000.0]
    monkeypatch.setattr(rl.time, "monotonic", lambda: t[0])
    with caplog.at_level(logging.WARNING, logger="cvenom.api.ratelimit"):
        rl.warn_rate_limited("x", "m")
        rl.warn_rate_limited("x", "m")
        t[0] += 61
        rl.warn_rate_limited("x", "m")
    assert len(caplog.records) == 2


# ------------------------------------------------------------------ cache


CP = ("/pub",)


async def test_second_anonymous_call_served_from_cache(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    async with client(app) as c:
        r1 = await c.get("/pub/json")
        r2 = await c.get("/pub/json")
    assert app.state.calls["n"] == 1
    assert r1.headers["x-cache"] == "MISS" and r2.headers["x-cache"] == "HIT"
    for r in (r1, r2):
        assert r.headers["cache-control"] == "public, max-age=30"
        assert r.json() == {"n": 1}
        assert r.headers["content-type"] == "application/json"
    keys = [k async for k in redis.scan_iter("cvenom:cache:*")]
    assert len(keys) == 1 and 0 < await redis.ttl(keys[0]) <= 30


async def test_paths_not_listed_are_not_cached(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    async with client(app) as c:
        await c.get("/other/json")
        r = await c.get("/other/json")
    assert app.state.calls["n"] == 2 and "x-cache" not in r.headers


async def test_no_cache_by_default(db_session, redis):
    app = make_app(db_session, redis)
    async with client(app) as c:
        await c.get("/pub/json")
        await c.get("/pub/json")
    assert app.state.calls["n"] == 2


async def test_authorization_header_never_cached(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    user = make_user(db_session)
    tok, _ = token_for(db_session, user)
    h = {"Authorization": f"Bearer {tok}"}
    async with client(app) as c:
        await c.get("/pub/json")  # primes the cache anonymously
        r1 = await c.get("/pub/json", headers=h)
        r2 = await c.get("/pub/json", headers=h)
    assert app.state.calls["n"] == 3  # authed calls bypass both read and write
    assert "x-cache" not in r1.headers and "x-cache" not in r2.headers
    assert r1.headers["cache-control"] == "no-store"


async def test_cookie_never_cached(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    async with client(app) as c:
        await c.get("/pub/json", headers={"Cookie": "a=b"})
        await c.get("/pub/json", headers={"Cookie": "a=b"})
    assert app.state.calls["n"] == 2
    assert [k async for k in redis.scan_iter("cvenom:cache:*")] == []


async def test_query_order_normalized(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    async with client(app) as c:
        await c.get("/pub/json?a=1&b=2")
        r = await c.get("/pub/json?b=2&a=1")
        r3 = await c.get("/pub/json?a=1&b=3")
    assert r.headers["x-cache"] == "HIT"
    assert r3.headers["x-cache"] == "MISS"
    assert app.state.calls["n"] == 2


async def test_non_200_not_cached(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    async with client(app) as c:
        r1 = await c.get("/pub/missing")
        await c.get("/pub/missing")
    assert r1.status_code == 404 and "x-cache" not in r1.headers
    assert app.state.calls["n"] == 2


async def test_non_json_not_cached(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    async with client(app) as c:
        r1 = await c.get("/pub/text")
        await c.get("/pub/text")
    assert "x-cache" not in r1.headers and "public" not in r1.headers.get("cache-control", "")
    assert app.state.calls["n"] == 2


async def test_set_cookie_response_not_cached(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP)
    async with client(app) as c:
        r1 = await c.get("/pub/cookie")
        await c.get("/pub/cookie")
    assert "set-cookie" in r1.headers and "x-cache" not in r1.headers
    assert app.state.calls["n"] == 2


async def test_oversize_not_cached(db_session, redis):
    from cvenom.api.cache import ResponseCacheMiddleware

    app = make_app(db_session, redis, cache_paths=CP)
    app.user_middleware.clear()
    app.middleware_stack = None
    app.add_middleware(
        ResponseCacheMiddleware, redis_getter=lambda: redis, paths=CP, max_bytes=3
    )
    async with client(app) as c:
        await c.get("/pub/json")
        r = await c.get("/pub/json")
    assert app.state.calls["n"] == 2 and "x-cache" not in r.headers


async def test_redis_error_bypasses_cache(db_session):
    app = make_app(db_session, DownRedis(), cache_paths=CP)
    async with client(app) as c:
        r1 = await c.get("/pub/json")
        r2 = await c.get("/pub/json")
    assert r1.status_code == 200 and r2.status_code == 200
    assert app.state.calls["n"] == 2 and "x-cache" not in r2.headers


async def test_redis_store_error_does_not_fail_request(db_session, redis):
    app = make_app(db_session, SetFailsRedis(redis), cache_paths=CP)
    async with client(app) as c:
        r = await c.get("/pub/json")
    assert r.status_code == 200 and "x-cache" not in r.headers


async def test_nothing_cached_when_public_read_false(db_session, redis):
    app = make_app(db_session, redis, cache_paths=CP, public_read=False)
    async with client(app) as c:
        r1 = await c.get("/pub/json")
        r2 = await c.get("/pub/json")
    assert app.state.calls["n"] == 2 and "x-cache" not in r2.headers
    assert [k async for k in redis.scan_iter("cvenom:cache:*")] == []
    assert r1.status_code == 200  # test route has no auth dependency


def test_redis_client_created_lazily_and_closed_on_shutdown(db_session):
    import asyncio

    app = create_app(get_settings())
    assert app.state.redis is None  # nothing connects at app creation
    client_ = rl.get_redis(app)
    assert client_ is rl.get_redis(app) and app.state.redis_owned

    async def run():
        async with app.router.lifespan_context(app):
            pass

    asyncio.run(run())
