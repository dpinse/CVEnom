import base64
import os
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import fakeredis
import httpx
import pytest
from sqlalchemy import select

from cvenom.api import create_app
from cvenom.auth.passwords import hash_password
from cvenom.auth.tokens import create_session, issue_access
from cvenom.config import get_settings
from cvenom.models import Invite, User, UserSession

PW = "correct horse battery"
COOKIE_PREFIX = "cvenom_refresh="
ATTRS = "; HttpOnly; Secure; SameSite=Strict; Path=/api/auth; Max-Age=2592000"
CLEARED = "cvenom_refresh=; HttpOnly; Secure; SameSite=Strict; Path=/api/auth; Max-Age=0"
CSRF = {"X-CVEnom-CSRF": "1"}


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_app(db_session, redis=None, **overrides):
    settings = get_settings().model_copy(update=overrides)

    @contextmanager
    def factory():
        yield db_session

    return create_app(
        settings, redis=redis or fakeredis.FakeAsyncRedis(), session_factory=factory
    )


def make_failing_commit_app(db_session):
    settings = get_settings()

    @contextmanager
    def factory():
        yield db_session
        raise RuntimeError("commit failed")

    return create_app(settings, redis=fakeredis.FakeAsyncRedis(), session_factory=factory)


def client(app, peer=("1.2.3.4", 1234)):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=peer), base_url="https://test"
    )


def mk_user(db, email="u@example.com", role="member", pw=PW):
    u = User(email=email, password_hash=hash_password(pw), role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def bearer(db, user):
    now = datetime.now(UTC)
    row, _ = create_session(db, user, now, "ua", "9.9.9.9")
    return {"Authorization": f"Bearer {issue_access(db, user, row.id, now)}"}, row


def set_cookie(r):
    return r.headers["set-cookie"]


def cookie_value(r):
    sc = set_cookie(r)
    assert sc.startswith(COOKIE_PREFIX)
    return sc[len(COOKIE_PREFIX):].split(";", 1)[0]


async def login(c, email="u@example.com", pw=PW):
    return await c.post("/api/auth/login", json={"email": email, "password": pw})


# ---------------------------------------------------------------- flow


async def test_login_me_refresh_logout_flow(db_session):
    mk_user(db_session)
    app = make_app(db_session)
    async with client(app) as c:
        r = await login(c)
        assert r.status_code == 200
        body = r.json()
        assert body["token_type"] == "bearer" and body["expires_in"] == 900
        assert set_cookie(r) == COOKIE_PREFIX + cookie_value(r) + ATTRS
        auth = {"Authorization": f"Bearer {body['access_token']}"}

        me = await c.get("/api/auth/me", headers=auth)
        assert me.status_code == 200
        assert set(me.json()) == {"id", "email", "role"}
        assert me.json()["email"] == "u@example.com"

        r2 = await c.post("/api/auth/refresh", headers=CSRF)
        assert r2.status_code == 200
        assert set_cookie(r2) == COOKIE_PREFIX + cookie_value(r2) + ATTRS
        assert cookie_value(r2) != cookie_value(r)
        auth2 = {"Authorization": f"Bearer {r2.json()['access_token']}"}

        out = await c.post("/api/auth/logout", headers=auth2)
        assert out.status_code == 204
        assert set_cookie(out) == CLEARED
        # access tokens of a revoked session are rejected
        assert (await c.get("/api/auth/me", headers=auth2)).status_code == 401
        assert (await c.get("/api/auth/me", headers=auth)).status_code == 401


async def test_login_records_ua_and_ip(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        await c.post(
            "/api/auth/login",
            json={"email": "u@example.com", "password": PW},
            headers={"User-Agent": "Mozilla/test"},
        )
    row = db_session.scalars(select(UserSession)).one()
    assert row.user_agent == "Mozilla/test" and row.ip == "1.2.3.4"


async def test_login_failures_byte_identical(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        a = await login(c, "nobody@example.com", PW)
        b = await login(c, "u@example.com", "wrong password here")
        d = await login(c, "u@example.com", "x" * 300)
    for r in (a, b, d):
        assert r.status_code == 401
        assert r.json() == {"error": "invalid_credentials"}
        assert "set-cookie" not in r.headers
    assert a.content == b.content == d.content
    assert dict(a.headers) == dict(b.headers) == dict(d.headers)


async def test_login_long_password_skips_authenticate(db_session, monkeypatch):
    from cvenom.api import routes_auth

    mk_user(db_session)
    called = {"d": 0}

    def boom(*a):
        raise AssertionError("authenticate called")

    monkeypatch.setattr(routes_auth, "authenticate", boom)
    monkeypatch.setattr(routes_auth, "dummy_verify", lambda *a: called.__setitem__("d", 1))
    async with client(make_app(db_session)) as c:
        r = await login(c, pw="x" * 257)
    assert r.status_code == 401 and called["d"] == 1


async def test_login_body_limits_and_validation(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post("/api/auth/login", json={"email": "a" * 400, "password": "x"})
        assert r.status_code == 422
        r = await c.post("/api/auth/login", json={"email": "a@b.c", "password": "x" * 2000})
        assert r.status_code == 422
        assert "xxxx" not in r.text
        r = await c.post("/api/auth/login", json={"email": "a@b.c"})
        assert r.status_code == 422


async def test_login_rate_limited_before_db(db_session):
    mk_user(db_session)
    app = make_app(db_session, rate_login_per_15min_ip=2)
    async with client(app) as c:
        assert (await login(c, pw="wrong password 1")).status_code == 401
        assert (await login(c, pw="wrong password 2")).status_code == 401
        r = await login(c)  # correct password but over the limit
    assert r.status_code == 429 and "set-cookie" not in r.headers


async def test_login_503_when_redis_down(db_session):
    from test_ratelimit import DownRedis

    mk_user(db_session)
    async with client(make_app(db_session, redis=DownRedis())) as c:
        r = await login(c)
    assert r.status_code == 503


async def test_login_inactive_user_rejected(db_session):
    u = mk_user(db_session)
    u.is_active = False
    db_session.flush()
    async with client(make_app(db_session)) as c:
        assert (await login(c)).status_code == 401


# ---------------------------------------------------------------- refresh


async def test_refresh_requires_csrf_header_before_cookie(db_session):
    mk_user(db_session)
    app = make_app(db_session)
    async with client(app) as c:
        r = await login(c)
        tok = cookie_value(r)
        nohdr = await c.post("/api/auth/refresh")
        assert nohdr.status_code == 403 and nohdr.json() == {"error": "csrf"}
        wrong = await c.post("/api/auth/refresh", headers={"X-CVEnom-CSRF": "0"})
        assert wrong.status_code == 403
        # CSRF is checked before the cookie, even with no cookie at all
        async with client(app) as c2:
            assert (await c2.post("/api/auth/refresh")).status_code == 403
            r3 = await c2.post("/api/auth/refresh", headers=CSRF)
            assert r3.status_code == 401 and r3.json() == {"error": "invalid_token"}
        # the failed attempts did not consume the token
        ok = await c.post("/api/auth/refresh", headers=CSRF)
        assert ok.status_code == 200 and cookie_value(ok) != tok


async def test_refresh_replay_revokes_session(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        r = await login(c)
        old = cookie_value(r)
        r2 = await c.post("/api/auth/refresh", headers=CSRF)
        assert r2.status_code == 200
        newest = cookie_value(r2)
        # replay the rotated-out token once outside the grace window
        row = db_session.scalars(select(UserSession)).one()
        row.last_used_at = datetime.now(UTC) - timedelta(minutes=5)
        db_session.flush()
        c.cookies.clear()
        bad = await c.post("/api/auth/refresh", headers={**CSRF, "Cookie": f"cvenom_refresh={old}"})
        assert bad.status_code == 401 and bad.json() == {"error": "invalid_token"}
        assert set_cookie(bad) == CLEARED
        assert "Max-Age=0" in set_cookie(bad)
        # session is revoked: even the newest token fails
        c.cookies.clear()
        worst = await c.post("/api/auth/refresh", headers={**CSRF, "Cookie": f"cvenom_refresh={newest}"})
        assert worst.status_code == 401
        assert db_session.scalars(select(UserSession)).one().revoked_at is not None


async def test_refresh_grace_loser_401_does_not_clear_cookie(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        r = await login(c)
        old = cookie_value(r)
        win = await c.post("/api/auth/refresh", headers=CSRF)
        assert win.status_code == 200
        newest = cookie_value(win)
        # concurrent loser: predecessor presented within the grace window
        c.cookies.clear()
        loser = await c.post(
            "/api/auth/refresh", headers={**CSRF, "Cookie": f"cvenom_refresh={old}"}
        )
        assert loser.status_code == 401 and loser.json() == {"error": "invalid_token"}
        assert "set-cookie" not in loser.headers
        # session untouched; the winner's rotated token still works
        assert db_session.scalars(select(UserSession)).one().revoked_at is None
        c.cookies.clear()
        again = await c.post(
            "/api/auth/refresh", headers={**CSRF, "Cookie": f"cvenom_refresh={newest}"}
        )
        assert again.status_code == 200 and cookie_value(again) != newest


async def test_refresh_garbage_cookie_401_and_clears(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post(
            "/api/auth/refresh", headers={**CSRF, "Cookie": "cvenom_refresh=garbage"}
        )
    assert r.status_code == 401 and r.json() == {"error": "invalid_token"}
    assert set_cookie(r) == CLEARED


# ---------------------------------------------------------------- sessions


async def test_sessions_list_and_revoke(db_session):
    u = mk_user(db_session)
    other = mk_user(db_session, "o@example.com")
    auth, cur = bearer(db_session, u)
    now = datetime.now(UTC)
    old, _ = create_session(db_session, u, now - timedelta(hours=2), "old-ua", "5.5.5.5")
    revoked, _ = create_session(db_session, u, now, "rev", "6.6.6.6")
    revoked.revoked_at = now
    create_session(db_session, u, now - timedelta(days=40), "exp", None)
    theirs, _ = create_session(db_session, other, now, "theirs", None)
    db_session.flush()
    async with client(make_app(db_session)) as c:
        r = await c.get("/api/auth/sessions", headers=auth)
        assert r.status_code == 200
        items = r.json()
        assert [i["id"] for i in items] == [str(cur.id), str(old.id)]
        assert [i["current"] for i in items] == [True, False]
        for i in items:
            assert set(i) == {"id", "user_agent", "ip", "created_at", "last_used_at", "current"}
        assert "hash" not in r.text

        assert (await c.delete(f"/api/auth/sessions/{theirs.id}", headers=auth)).status_code == 404
        nf = await c.delete(f"/api/auth/sessions/{uuid.uuid4()}", headers=auth)
        assert nf.status_code == 404 and nf.json() == {"error": "not_found"}
        assert (await c.delete("/api/auth/sessions/not-a-uuid", headers=auth)).status_code == 404
        assert (await c.delete(f"/api/auth/sessions/{old.id}", headers=auth)).status_code == 204
        r = await c.get("/api/auth/sessions", headers=auth)
        assert [i["id"] for i in r.json()] == [str(cur.id)]
    assert theirs.revoked_at is None


async def test_authenticated_routes_require_auth(db_session):
    async with client(make_app(db_session)) as c:
        assert (await c.get("/api/auth/sessions")).status_code == 401
        assert (await c.get("/api/auth/me")).status_code == 401
        assert (await c.post("/api/auth/logout")).status_code == 401


# ---------------------------------------------------------------- invites


async def test_invite_flow(db_session):
    admin = mk_user(db_session, "a@example.com", "admin")
    auth, _ = bearer(db_session, admin)
    async with client(make_app(db_session)) as c:
        r = await c.post(
            "/api/auth/invites", json={"email": "new@example.com", "role": "member"}, headers=auth
        )
        assert r.status_code == 201
        tok = r.json()["token"]
        assert set(r.json()) == {"token", "expires_at"}
        weak = await c.post("/api/auth/invites/accept", json={"token": tok, "password": "short"})
        assert weak.status_code == 422 and weak.json() == {"error": "weak_password"}
        ok = await c.post("/api/auth/invites/accept", json={"token": tok, "password": PW})
        assert ok.status_code == 201
        assert set(ok.json()) == {"id", "email", "role"}
        assert ok.json()["email"] == "new@example.com" and ok.json()["role"] == "member"
        assert "set-cookie" not in ok.headers and "access_token" not in ok.text
        again = await c.post("/api/auth/invites/accept", json={"token": tok, "password": PW})
        assert again.status_code == 400 and again.json() == {"error": "invalid_invite"}
        bogus = await c.post("/api/auth/invites/accept", json={"token": "nope", "password": PW})
        assert bogus.status_code == 400
        assert (await login(c, "new@example.com")).status_code == 200


async def test_invite_validation_and_permissions(db_session):
    member = mk_user(db_session)
    admin = mk_user(db_session, "a@example.com", "admin")
    m_auth, _ = bearer(db_session, member)
    a_auth, _ = bearer(db_session, admin)
    body = {"email": "x@example.com", "role": "member"}
    async with client(make_app(db_session)) as c:
        assert (await c.post("/api/auth/invites", json=body, headers=m_auth)).status_code == 403
        assert (await c.post("/api/auth/invites", json=body)).status_code == 401
        bad_role = await c.post(
            "/api/auth/invites", json={"email": "x@example.com", "role": "root"}, headers=a_auth
        )
        assert bad_role.status_code == 422
        bad_mail = await c.post(
            "/api/auth/invites", json={"email": "nope", "role": "member"}, headers=a_auth
        )
        assert bad_mail.status_code == 422
        long_tok = await c.post(
            "/api/auth/invites/accept", json={"token": "t" * 300, "password": PW}
        )
        assert long_tok.status_code == 422
    assert db_session.scalars(select(Invite)).all() == []


async def test_accept_rate_limited(db_session):
    async with client(make_app(db_session, rate_anon_per_min=2)) as c:
        codes = [
            (
                await c.post("/api/auth/invites/accept", json={"token": "t", "password": PW})
            ).status_code
            for _ in range(3)
        ]
    assert codes == [400, 400, 429]


# ---------------------------------------------------------------- fix round 1


async def test_stale_bearer_does_not_break_refresh(db_session):
    mk_user(db_session)
    app = make_app(db_session)
    async with client(app) as c:
        r = await login(c)
        tok = cookie_value(r)
        r2 = await c.post(
            "/api/auth/refresh",
            headers={**CSRF, "Authorization": "Bearer expired.garbage.x"},
        )
    assert r2.status_code == 200
    assert set_cookie(r2) == COOKIE_PREFIX + cookie_value(r2) + ATTRS
    assert cookie_value(r2) != tok


async def test_stale_bearer_does_not_break_accept(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post(
            "/api/auth/invites/accept",
            json={"token": "t", "password": PW},
            headers={"Authorization": "Bearer junk"},
        )
    assert r.status_code == 400 and r.json() == {"error": "invalid_invite"}


async def test_refreshed_access_token_keeps_sid(db_session):
    from cvenom.auth.tokens import decode_access

    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        r = await login(c)
        r2 = await c.post("/api/auth/refresh", headers=CSRF)
    now = datetime.now(UTC)
    a = decode_access(db_session, r.json()["access_token"], now)
    b = decode_access(db_session, r2.json()["access_token"], now)
    assert a.sid == b.sid


async def test_refresh_oversized_cookie_clears(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post(
            "/api/auth/refresh", headers={**CSRF, "Cookie": "cvenom_refresh=" + "a" * 300}
        )
    assert r.status_code == 401 and set_cookie(r) == CLEARED


async def test_login_inactive_byte_identical(db_session):
    mk_user(db_session)
    u = mk_user(db_session, "off@example.com")
    u.is_active = False
    db_session.flush()
    async with client(make_app(db_session)) as c:
        a = await login(c, "nobody@example.com", PW)
        b = await login(c, "off@example.com", PW)
    assert a.content == b.content and dict(a.headers) == dict(b.headers)


async def test_extra_fields_rejected(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post(
            "/api/auth/invites/accept", json={"token": "t", "password": PW, "role": "admin"}
        )
        assert r.status_code == 422
        r = await c.post(
            "/api/auth/login", json={"email": "a@b.c", "password": "x", "admin": True}
        )
        assert r.status_code == 422


async def test_failed_commit_login_is_500_without_cookie(db_session):
    mk_user(db_session)
    async with client(make_failing_commit_app(db_session)) as c:
        r = await login(c)
    assert r.status_code == 500 and r.json() == {"error": "internal_error"}
    assert "set-cookie" not in r.headers


async def test_failed_commit_logout_not_204(db_session):
    u = mk_user(db_session)
    auth, _ = bearer(db_session, u)
    async with client(make_failing_commit_app(db_session)) as c:
        r = await c.post("/api/auth/logout", headers=auth)
    assert r.status_code == 500
