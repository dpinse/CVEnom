import base64
import os
from contextlib import contextmanager
from datetime import UTC, datetime

import httpx
import pytest
from fastapi import Depends
from pydantic import BaseModel, field_validator
from starlette.requests import Request

from cvenom.api import client_ip, create_app
from cvenom.api.deps import public_or_user, require_admin, require_user
from cvenom.auth.tokens import create_session, issue_access
from cvenom.config import get_settings
from cvenom.models import User

CSP = "default-src 'none'; frame-ancestors 'none'"
TRUSTED = ["10.0.0.0/8", "2001:db8::/32"]


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class Body(BaseModel):
    password: str
    n: int


class Checked(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def _check(cls, v):
        raise ValueError(f"bad-{v}")


def make_app(db_session, **overrides):
    settings = get_settings().model_copy(update=overrides)

    @contextmanager
    def factory():
        yield db_session

    app = create_app(settings, session_factory=factory)

    @app.get("/t/boom")
    def boom():
        raise RuntimeError("secret-traceback-marker")

    @app.get("/t/public")
    def public(user=Depends(public_or_user)):
        return {"user": user.email if user else None}

    @app.get("/t/me")
    def me(user=Depends(require_user)):
        return {"user": user.email}

    @app.get("/t/admin")
    def admin(user=Depends(require_admin)):
        return {"user": user.email}

    @app.get("/t/ip")
    def ip(request: Request):
        return {"ip": client_ip(request)}

    @app.get("/t/cache")
    def cache():
        from fastapi.responses import JSONResponse

        return JSONResponse({}, headers={"Cache-Control": "max-age=60"})

    @app.post("/t/body")
    def body(b: Body):
        return {"ok": True}

    @app.post("/t/checked")
    def checked(b: Checked):
        return {"ok": True}

    @app.post("/t/sink")
    async def sink(request: Request):
        return {"n": len(await request.body())}

    return app


def client(app, peer=("1.2.3.4", 1234)):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=peer),
        base_url="http://test",
    )


def make_user(db_session, email="u@example.com", role="member", active=True):
    u = User(email=email, password_hash="x", role=role, is_active=active)
    db_session.add(u)
    db_session.flush()
    return u


def token_for(db_session, user):
    now = datetime.now(UTC)
    row, _ = create_session(db_session, user, now, "ua", "1.1.1.1")
    return issue_access(db_session, user, row.id, now), row


def assert_security_headers(r):
    assert r.headers["content-security-policy"] == CSP
    assert r.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-frame-options"] == "DENY"


async def test_health_and_headers(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "public_read": True}
    assert_security_headers(r)
    assert "cache-control" not in r.headers


async def test_health_reports_public_read_false(db_session):
    async with client(make_app(db_session, public_read=False)) as c:
        r = await c.get("/api/health")
    assert r.json() == {"status": "ok", "public_read": False}


async def test_docs_disabled_by_default(db_session):
    async with client(make_app(db_session)) as c:
        for path in ("/docs", "/redoc", "/openapi.json"):
            r = await c.get(path)
            assert r.status_code == 404, path
    async with client(make_app(db_session, api_docs=True)) as c:
        assert (await c.get("/openapi.json")).status_code == 200


async def test_headers_on_404_and_500(db_session):
    async with client(make_app(db_session)) as c:
        r404 = await c.get("/nope")
        r500 = await c.get("/t/boom")
    assert r404.status_code == 404
    assert_security_headers(r404)
    assert r500.status_code == 500
    assert r500.json() == {"error": "internal_error"}
    assert "secret-traceback-marker" not in r500.text
    assert "Traceback" not in r500.text
    assert_security_headers(r500)


async def test_cache_control_rules(db_session):
    async with client(make_app(db_session)) as c:
        assert (await c.get("/api/auth/x")).headers["cache-control"] == "no-store"
        r = await c.get("/t/public", headers={"Authorization": "Bearer junk"})
        assert r.headers["cache-control"] == "no-store"
        # route-set Cache-Control is preserved when neither condition applies
        assert (await c.get("/t/cache")).headers["cache-control"] == "max-age=60"
        # but forced to no-store when authed
        r = await c.get("/t/cache", headers={"Authorization": "Bearer x"})
        assert r.headers["cache-control"] == "no-store"


async def test_cors_disallowed_origin_gets_no_acao(db_session):
    app = make_app(db_session, cors_origins=["https://ok.example"])
    async with client(app) as c:
        bad = await c.get("/api/health", headers={"Origin": "https://evil.example"})
        good = await c.get("/api/health", headers={"Origin": "https://ok.example"})
    assert "access-control-allow-origin" not in bad.headers
    assert good.headers["access-control-allow-origin"] == "https://ok.example"
    assert good.headers["access-control-allow-credentials"] == "true"
    assert_security_headers(bad)


async def test_cors_not_installed_when_empty(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.get("/api/health", headers={"Origin": "https://ok.example"})
    assert "access-control-allow-origin" not in r.headers


async def test_oversize_content_length_413(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post("/t/sink", content=b"x" * 70_000)
    assert r.status_code == 413
    assert r.json() == {"error": "payload_too_large"}
    assert_security_headers(r)


async def test_chunked_body_without_content_length_413(db_session):
    async def gen():
        for _ in range(70):
            yield b"x" * 1024

    async with client(make_app(db_session)) as c:
        r = await c.post("/t/sink", content=gen())
    assert r.status_code == 413
    assert r.json() == {"error": "payload_too_large"}
    assert_security_headers(r)


async def test_streamed_oversize_does_not_log_error(db_session, caplog):
    async def gen():
        for _ in range(70):
            yield b"x" * 1024

    async with client(make_app(db_session)) as c:
        with caplog.at_level("DEBUG"):
            r = await c.post("/t/sink", content=gen())
    assert r.status_code == 413
    assert not [rec for rec in caplog.records if rec.levelname == "ERROR"]


async def test_413_has_cors_headers(db_session):
    app = make_app(db_session, cors_origins=["https://ok.example"])
    async with client(app) as c:
        r = await c.post(
            "/t/sink", content=b"x" * 70_000, headers={"Origin": "https://ok.example"}
        )
    assert r.status_code == 413
    assert r.headers["access-control-allow-origin"] == "https://ok.example"


async def test_small_body_ok(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post("/t/sink", content=b"x" * 1000)
    assert r.status_code == 200
    assert r.json() == {"n": 1000}


async def test_validation_error_does_not_echo_input(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post("/t/body", json={"password": "hunter2-secret", "n": "not-an-int"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "validation_error"
    assert "hunter2-secret" not in r.text
    assert "not-an-int" not in r.text
    for e in body["detail"]:
        assert set(e) == {"loc", "msg", "type"}


async def test_validator_message_not_echoed(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post("/t/checked", json={"password": "hunter2"})
    assert r.status_code == 422
    assert "bad-hunter2" not in r.text
    assert "hunter2" not in r.text
    assert r.json()["detail"][0]["msg"] == "invalid value"


async def test_validation_loc_truncated(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post("/t/body", json={"password": {"attacker-key": 1}, "n": 1})
    assert r.status_code == 422
    assert "attacker-key" not in r.text


# ---- client_ip ----

async def ip_of(db_session, peer, headers=None, trusted=TRUSTED, cf=True):
    app = make_app(db_session, trusted_proxy_cidrs=trusted, trust_cf_connecting_ip=cf)
    async with client(app, peer=peer) as c:
        return (await c.get("/t/ip", headers=headers or {})).json()["ip"]


async def test_client_ip_untrusted_peer_ignores_spoofed_headers(db_session):
    got = await ip_of(
        db_session,
        ("1.2.3.4", 1),
        {"X-Forwarded-For": "6.6.6.6", "CF-Connecting-IP": "7.7.7.7"},
    )
    assert got == "1.2.3.4"


async def test_client_ip_trusted_peer_cf_header(db_session):
    got = await ip_of(db_session, ("10.0.0.5", 1), {"CF-Connecting-IP": "8.8.8.8"})
    assert got == "8.8.8.8"


async def test_client_ip_trusted_peer_xff_rightmost_untrusted(db_session):
    got = await ip_of(
        db_session, ("10.0.0.5", 1), {"X-Forwarded-For": "evil, 9.9.9.9, 10.1.1.1"}
    )
    assert got == "9.9.9.9"


async def test_client_ip_cf_ignored_unless_flag(db_session):
    h = {"CF-Connecting-IP": "8.8.8.8"}
    assert await ip_of(db_session, ("10.0.0.5", 1), h, cf=False) == "10.0.0.5"
    assert await ip_of(db_session, ("10.0.0.5", 1), h, cf=True) == "8.8.8.8"
    h = {"CF-Connecting-IP": "8.8.8.8", "X-Forwarded-For": "9.9.9.9"}
    assert await ip_of(db_session, ("10.0.0.5", 1), h, cf=False) == "9.9.9.9"


@pytest.mark.parametrize(
    "xff,expected",
    [
        ("6.6.6.6, 9.9.9.9:443", "9.9.9.9"),
        ("6.6.6.6, [2606:4700::1]:443", "2606:4700::1"),
        ("6.6.6.6, [2606:4700::1]", "2606:4700::1"),
        ("6.6.6.6, unknown", "10.0.0.5"),
        ("6.6.6.6,", "10.0.0.5"),
        ("6.6.6.6, , 10.1.1.1", "10.0.0.5"),
        ("6.6.6.6, fe80::1%eth0", "10.0.0.5"),
    ],
)
async def test_client_ip_xff_stops_at_invalid_hop(db_session, xff, expected):
    got = await ip_of(db_session, ("10.0.0.5", 1), {"X-Forwarded-For": xff})
    assert got == expected
    assert got != "6.6.6.6"


async def test_client_ip_ipv4_mapped_peer_is_trusted(db_session):
    got = await ip_of(
        db_session, ("::ffff:10.0.0.5", 1), {"X-Forwarded-For": "::ffff:9.9.9.9"}
    )
    assert got == "9.9.9.9"


async def test_client_ip_garbage_headers_fall_back_to_peer(db_session):
    got = await ip_of(
        db_session,
        ("10.0.0.5", 1),
        {"CF-Connecting-IP": "not-an-ip", "X-Forwarded-For": "junk, ???"},
    )
    assert got == "10.0.0.5"


async def test_client_ip_ipv6(db_session):
    assert await ip_of(db_session, ("2001:db8::1", 1), {"CF-Connecting-IP": "2606:4700::1"}) == (
        "2606:4700::1"
    )
    assert await ip_of(db_session, ("2a00::1", 1), {"CF-Connecting-IP": "8.8.8.8"}) == "2a00::1"


async def test_client_ip_no_trusted_cidrs(db_session):
    got = await ip_of(db_session, ("10.0.0.5", 1), {"CF-Connecting-IP": "8.8.8.8"}, trusted=[])
    assert got == "10.0.0.5"


# ---- auth deps ----

async def test_anonymous_allowed_when_public_read(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.get("/t/public")
    assert r.status_code == 200
    assert r.json() == {"user": None}


async def test_anonymous_401_when_not_public_read(db_session):
    async with client(make_app(db_session, public_read=False)) as c:
        r = await c.get("/t/public")
    assert r.status_code == 401
    assert r.json() == {"error": "unauthorized"}
    assert r.headers["www-authenticate"] == "Bearer"


async def test_bad_token_401_even_when_public_read(db_session):
    async with client(make_app(db_session, public_read=True)) as c:
        for h in ("Bearer garbage", "Basic abc", "Bearer", "garbage"):
            r = await c.get("/t/public", headers={"Authorization": h})
            assert r.status_code == 401, h
            assert r.json() == {"error": "invalid_token"}
            assert r.headers["www-authenticate"] == "Bearer"


async def test_valid_token_works(db_session):
    user = make_user(db_session)
    tok, _ = token_for(db_session, user)
    async with client(make_app(db_session)) as c:
        r = await c.get("/t/me", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r.json() == {"user": "u@example.com"}
        r = await c.get("/t/me")
        assert r.status_code == 401


async def test_revoked_session_token_401(db_session):
    user = make_user(db_session)
    tok, row = token_for(db_session, user)
    row.revoked_at = datetime.now(UTC)
    db_session.flush()
    async with client(make_app(db_session)) as c:
        r = await c.get("/t/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token"}


async def test_inactive_user_token_401(db_session):
    user = make_user(db_session)
    tok, _ = token_for(db_session, user)
    user.is_active = False
    db_session.flush()
    async with client(make_app(db_session)) as c:
        r = await c.get("/t/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


async def test_member_forbidden_admin_allowed(db_session):
    member = make_user(db_session, "m@example.com", "member")
    admin = make_user(db_session, "a@example.com", "admin")
    mt, _ = token_for(db_session, member)
    at, _ = token_for(db_session, admin)
    async with client(make_app(db_session)) as c:
        r = await c.get("/t/admin", headers={"Authorization": f"Bearer {mt}"})
        assert r.status_code == 403
        assert r.json() == {"error": "forbidden"}
        assert_security_headers(r)
        r = await c.get("/t/admin", headers={"Authorization": f"Bearer {at}"})
        assert r.status_code == 200
