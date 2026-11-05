"""Mandatory TOTP MFA: two-step sign-in, enrollment, recovery codes, limits."""

import base64
import hashlib
import logging
import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import fakeredis
import httpx
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import select

from cvenom import secretbox
from cvenom.api import create_app
from cvenom.auth import totp
from cvenom.auth.passwords import hash_password
from cvenom.auth.users import create_invite
from cvenom.config import get_settings
from cvenom.models import MfaRecoveryCode, MfaTicket, User, UserSession
from mfa_helpers import code_for, enroll_user, full_login

PW = "correct horse battery"
EMAIL = "u@example.com"
ATTRS = "; HttpOnly; Secure; SameSite=Strict; Path=/api/auth; Max-Age=2592000"
FAIL = {"error": "invalid_mfa"}


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


def client(app, peer=("1.2.3.4", 1234)):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=peer), base_url="https://test"
    )


def mk_user(db, email=EMAIL, role="member"):
    u = User(email=email, password_hash=hash_password(PW), role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


async def ticket_for(c, email=EMAIL):
    r = await c.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def frozen(monkeypatch):
    """Pin the MFA clock to the middle of the current 30 s step; returns a setter."""
    from cvenom.api import routes_mfa

    base = (int(datetime.now(UTC).timestamp()) // 30) * 30 + 15
    state = {"t": base}
    monkeypatch.setattr(routes_mfa, "_now", lambda: datetime.fromtimestamp(state["t"], UTC))

    class Clock:
        t0 = base

        def set(self, t):
            state["t"] = t

    return Clock()


def assert_no_session(r):
    assert "set-cookie" not in r.headers
    assert "access_token" not in r.text


# ---------------------------------------------------------------- login step 1


async def test_login_returns_ticket_not_session(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        r = await c.post("/api/auth/login", json={"email": EMAIL, "password": PW})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"ticket", "enroll_required", "expires_in"}
    assert body["enroll_required"] is True and body["expires_in"] == 300
    assert_no_session(r)
    assert db_session.scalars(select(UserSession)).all() == []
    row = db_session.scalars(select(MfaTicket)).one()
    # stored hashed, bound to the user, 5-minute lifetime
    assert row.token_hash == hashlib.sha256(body["ticket"].encode()).hexdigest()
    assert body["ticket"] not in row.token_hash
    ttl = row.expires_at - datetime.now(UTC)
    assert timedelta(minutes=4, seconds=50) < ttl <= timedelta(minutes=5)


async def test_enrolled_user_login_then_verify_issues_session(db_session):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session)) as c:
        t = await ticket_for(c)
        assert t["enroll_required"] is False
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t["ticket"], "code": code_for(secret)})
        assert r.status_code == 200
        body = r.json()
        assert set(body) == {"access_token", "token_type", "expires_in"}
        sc = r.headers["set-cookie"]
        assert sc.startswith("cvenom_refresh=") and sc.endswith(ATTRS)
        me = await c.get("/api/auth/me",
                         headers={"Authorization": f"Bearer {body['access_token']}"})
        assert me.status_code == 200 and me.json()["email"] == EMAIL
        # the refresh cookie from the second factor rotates normally
        rr = await c.post("/api/auth/refresh", headers={"X-CVEnom-CSRF": "1"})
        assert rr.status_code == 200
    assert db_session.scalars(select(MfaTicket)).all() == []  # consumed


async def test_verify_records_ua_and_ip(db_session):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session)) as c:
        r = await full_login(c, EMAIL, PW, secret=secret, headers={"User-Agent": "Mozilla/mfa"})
    assert r.status_code == 200
    row = db_session.scalars(select(UserSession)).one()
    assert row.user_agent == "Mozilla/mfa" and row.ip == "1.2.3.4"


# ---------------------------------------------------------------- tickets


async def test_ticket_is_single_use(db_session, frozen):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        ok = await c.post("/api/auth/mfa/verify",
                          json={"ticket": t, "code": code_for(secret, frozen.t0)})
        assert ok.status_code == 200
        again = await c.post("/api/auth/mfa/verify",
                             json={"ticket": t, "code": code_for(secret, frozen.t0 + 30)})
    assert again.status_code == 401 and again.json() == FAIL
    assert_no_session(again)


async def test_ticket_expires_after_five_minutes(db_session, frozen):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        row = db_session.scalars(select(MfaTicket)).one()
        frozen.set(row.expires_at.timestamp())  # the expiry instant itself is already dead
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t, "code": code_for(secret, row.expires_at.timestamp())})
    assert r.status_code == 401 and r.json() == FAIL


async def test_ticket_for_another_user_rejected(db_session):
    a = mk_user(db_session, "a@example.com")
    b = mk_user(db_session, "b@example.com")
    enroll_user(db_session, a)
    secret_b = enroll_user(db_session, b)
    async with client(make_app(db_session)) as c:
        ta = (await ticket_for(c, "a@example.com"))["ticket"]
        r = await c.post("/api/auth/mfa/verify", json={"ticket": ta, "code": code_for(secret_b)})
    assert r.status_code == 401 and r.json() == FAIL
    assert db_session.scalars(select(UserSession)).all() == []


async def test_ticket_dies_when_user_deactivated(db_session):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        u.is_active = False
        db_session.flush()
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t, "code": code_for(secret)})
    assert r.status_code == 401 and r.json() == FAIL


async def test_failures_are_byte_identical(db_session, frozen):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    other = mk_user(db_session, "o@example.com")
    other_secret = enroll_user(db_session, other)
    app = make_app(db_session, rate_mfa_per_15min_ip=100, rate_mfa_per_15min_user=100)
    async with client(app) as c:
        good = code_for(secret, frozen.t0)
        t1 = (await ticket_for(c))["ticket"]
        wrong = await c.post("/api/auth/mfa/verify", json={"ticket": t1, "code": "000000"
                             if good != "000000" else "111111"})
        bogus = await c.post("/api/auth/mfa/verify", json={"ticket": "nope", "code": good})
        foreign = await c.post("/api/auth/mfa/verify",
                               json={"ticket": t1, "code": code_for(other_secret, frozen.t0)})
        badfmt = await c.post("/api/auth/mfa/verify", json={"ticket": t1, "code": "zz"})
        ok = await c.post("/api/auth/mfa/verify", json={"ticket": t1, "code": good})
        assert ok.status_code == 200
        t2 = (await ticket_for(c))["ticket"]
        replay = await c.post("/api/auth/mfa/verify", json={"ticket": t2, "code": good})
        used = await c.post("/api/auth/mfa/verify", json={"ticket": t1, "code": good})
        unenrolled_t = (await ticket_for(c, "o@example.com"))["ticket"]
        other.mfa_enabled_at = None
        db_session.flush()
        not_enrolled = await c.post("/api/auth/mfa/verify",
                                    json={"ticket": unenrolled_t,
                                          "code": code_for(other_secret, frozen.t0)})
        start_enrolled = await c.post("/api/auth/mfa/enroll/start", json={"ticket": t2})
        finish_no_start = await c.post("/api/auth/mfa/enroll/finish",
                                       json={"ticket": unenrolled_t, "code": good})
        h2 = hashlib.sha256(t2.encode()).hexdigest()
        exp_at = db_session.get(MfaTicket, h2).expires_at.timestamp()
        frozen.set(int(exp_at) + 1)
        expired = await c.post("/api/auth/mfa/verify",
                               json={"ticket": t2, "code": code_for(secret, exp_at + 1)})
    rs = [wrong, bogus, foreign, badfmt, replay, used, not_enrolled, start_enrolled,
          finish_no_start, expired]
    for r in rs:
        assert r.status_code == 401, r.request.url
        assert r.content == rs[0].content
        assert dict(r.headers) == dict(rs[0].headers)
        assert_no_session(r)
    assert rs[0].json() == FAIL


# ---------------------------------------------------------------- TOTP rules


@pytest.mark.parametrize("offset,ok", [(-2, False), (-1, True), (0, True), (1, True), (2, False)])
async def test_drift_window(db_session, frozen, offset, ok):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t, "code": code_for(secret, frozen.t0 + 30 * offset)})
    assert r.status_code == (200 if ok else 401)


async def test_replay_of_same_step_rejected(db_session, frozen):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    code = code_for(secret, frozen.t0)
    async with client(make_app(db_session)) as c:
        t1 = (await ticket_for(c))["ticket"]
        assert (await c.post("/api/auth/mfa/verify",
                             json={"ticket": t1, "code": code})).status_code == 200
        assert db_session.get(User, u.id).mfa_last_step == totp.step_of(frozen.t0)
        t2 = (await ticket_for(c))["ticket"]
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t2, "code": code})
        assert r.status_code == 401
        # an earlier step is dead too; the next step works
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t2, "code": code_for(secret, frozen.t0 - 30)})
        assert r.status_code == 401
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t2, "code": code_for(secret, frozen.t0 + 30)})
        assert r.status_code == 200


# ---------------------------------------------------------------- rate limits


async def test_sixth_failure_is_rate_limited_per_user(db_session, frozen):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    good = code_for(secret, frozen.t0)
    bad = "000000" if good != "000000" else "111111"
    app = make_app(db_session, rate_login_per_15min_ip=100, rate_login_per_15min_email=100)
    # each attempt from a different IP: the per-user bucket must still trip
    for i in range(5):
        async with client(app, peer=(f"10.0.0.{i + 1}", 1)) as c:
            t = (await ticket_for(c))["ticket"]
            r = await c.post("/api/auth/mfa/verify", json={"ticket": t, "code": bad})
            assert r.status_code == 401
    async with client(app, peer=("10.0.0.99", 1)) as c:
        t = (await ticket_for(c))["ticket"]
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t, "code": good})
    assert r.status_code == 429 and "retry-after" in r.headers
    assert_no_session(r)
    assert db_session.scalars(select(UserSession)).all() == []


async def test_sixth_failure_is_rate_limited_per_ip(db_session, frozen):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    app = make_app(db_session)
    async with client(app) as c:
        for _ in range(5):
            r = await c.post("/api/auth/mfa/verify", json={"ticket": "guess", "code": "123456"})
            assert r.status_code == 401
        t = (await ticket_for(c))["ticket"]
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t, "code": code_for(secret, frozen.t0)})
    assert r.status_code == 429
    assert_no_session(r)


async def test_enroll_finish_failures_share_the_limit(db_session):
    mk_user(db_session)
    app = make_app(db_session)
    async with client(app) as c:
        t = (await ticket_for(c))["ticket"]
        s = await c.post("/api/auth/mfa/enroll/start", json={"ticket": t})
        for _ in range(5):
            r = await c.post("/api/auth/mfa/enroll/finish", json={"ticket": t, "code": "zzzzzz"})
            assert r.status_code == 401
        r = await c.post("/api/auth/mfa/enroll/finish",
                         json={"ticket": t, "code": code_for(s.json()["secret"])})
    assert r.status_code == 429
    assert_no_session(r)


async def test_success_does_not_consume_the_failure_budget(db_session, frozen):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    app = make_app(db_session)
    async with client(app) as c:
        for k in range(6):  # six successes in a row are fine
            t = (await ticket_for(c))["ticket"]
            r = await c.post("/api/auth/mfa/verify",
                             json={"ticket": t, "code": code_for(secret, frozen.t0)})
            u.mfa_last_step = None  # replay protection is not what this test is about
            db_session.flush()
            assert r.status_code == 200, k


class MfaDownRedis:
    """Redis that serves the login limiter but is down for the MFA limiter."""

    def __init__(self):
        self.inner = fakeredis.FakeAsyncRedis()

    async def eval(self, script, n, key, *args):
        k = key.decode() if isinstance(key, bytes) else key
        if ":mfa:" in k:
            raise RedisConnectionError("down")
        return await self.inner.eval(script, n, key, *args)

    async def get(self, *a, **k):
        return await self.inner.get(*a, **k)

    async def set(self, *a, **k):
        return await self.inner.set(*a, **k)


async def test_mfa_limits_fail_closed_when_redis_down(db_session):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session, redis=MfaDownRedis())) as c:
        t = (await ticket_for(c))["ticket"]
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t, "code": code_for(secret)})
        assert r.status_code == 503
        assert_no_session(r)
        u.mfa_enabled_at = None
        db_session.flush()
        r = await c.post("/api/auth/mfa/enroll/finish", json={"ticket": t, "code": "123456"})
        assert r.status_code == 503
    assert db_session.scalars(select(UserSession)).all() == []


# ---------------------------------------------------------------- enrollment


async def test_existing_user_without_mfa_must_enroll(db_session):
    mk_id = mk_user(db_session).id  # an account from before MFA existed
    async with client(make_app(db_session)) as c:
        t = await ticket_for(c)
        assert t["enroll_required"] is True
        # verify is not a way around enrollment
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t["ticket"], "code": "123456"})
        assert r.status_code == 401
        s = await c.post("/api/auth/mfa/enroll/start", json={"ticket": t["ticket"]})
        assert s.status_code == 200
        assert_no_session(s)
        body = s.json()
        assert set(body) == {"secret", "otpauth_uri"}
        assert body["otpauth_uri"].startswith("otpauth://totp/CVEnom:u%40example.com?secret=")
        assert f"secret={body['secret']}&" in body["otpauth_uri"]
        bad = await c.post("/api/auth/mfa/enroll/finish",
                           json={"ticket": t["ticket"], "code": "000000"
                                 if code_for(body["secret"]) != "000000" else "111111"})
        assert bad.status_code == 401 and bad.json() == FAIL
        assert db_session.get(User, mk_id).mfa_enabled_at is None
        fin = await c.post("/api/auth/mfa/enroll/finish",
                           json={"ticket": t["ticket"], "code": code_for(body["secret"])})
        assert fin.status_code == 200
        out = fin.json()
        assert set(out) == {"access_token", "token_type", "expires_in", "recovery_codes"}
        assert fin.headers["set-cookie"].endswith(ATTRS)
        codes = out["recovery_codes"]
        assert len(codes) == 10 and len(set(codes)) == 10
        for code in codes:
            assert len(code.replace("-", "")) == 16
    user = db_session.get(User, mk_id)
    assert user.mfa_enabled_at is not None and user.mfa_last_step is not None
    # encrypted at rest with the secret box
    assert user.mfa_secret_enc.startswith("v1:")
    assert body["secret"] not in user.mfa_secret_enc
    assert secretbox.decrypt(user.mfa_secret_enc) == base64.b32decode(body["secret"])
    # recovery codes hashed at rest
    rows = db_session.scalars(select(MfaRecoveryCode)).all()
    assert len(rows) == 10
    stored = " ".join(r.code_hash for r in rows)
    for code in codes:
        assert code not in stored and code.replace("-", "") not in stored
    assert db_session.scalars(select(MfaTicket)).all() == []


async def test_enroll_start_secret_is_held_encrypted_on_the_ticket(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        s = (await c.post("/api/auth/mfa/enroll/start", json={"ticket": t})).json()
    row = db_session.scalars(select(MfaTicket)).one()
    assert row.enroll_secret_enc.startswith("v1:")
    assert s["secret"] not in row.enroll_secret_enc
    assert db_session.scalars(select(User)).one().mfa_secret_enc is None


async def test_enroll_start_again_replaces_the_pending_secret(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        s1 = (await c.post("/api/auth/mfa/enroll/start", json={"ticket": t})).json()
        s2 = (await c.post("/api/auth/mfa/enroll/start", json={"ticket": t})).json()
        assert s1["secret"] != s2["secret"]
        old = await c.post("/api/auth/mfa/enroll/finish",
                           json={"ticket": t, "code": code_for(s1["secret"])})
        if code_for(s1["secret"]) != code_for(s2["secret"]):
            assert old.status_code == 401
        new = await c.post("/api/auth/mfa/enroll/finish",
                           json={"ticket": t, "code": code_for(s2["secret"])})
    assert new.status_code == 200


async def test_secret_never_returned_after_enrollment(db_session, caplog):
    caplog.set_level(logging.DEBUG)
    admin = mk_user(db_session, "a@example.com", "admin")
    admin_secret = enroll_user(db_session, admin)
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        s = (await c.post("/api/auth/mfa/enroll/start", json={"ticket": t})).json()
        secret = s["secret"]
        fin = await c.post("/api/auth/mfa/enroll/finish",
                           json={"ticket": t, "code": code_for(secret)})
        codes = fin.json()["recovery_codes"]
        auth = {"Authorization": f"Bearer {fin.json()['access_token']}"}
        seen = []
        seen.append(await c.post("/api/auth/login", json={"email": EMAIL, "password": PW}))
        t2 = seen[-1].json()["ticket"]
        seen.append(await c.post("/api/auth/mfa/enroll/start", json={"ticket": t2}))
        seen.append(await c.post("/api/auth/mfa/verify",
                                 json={"ticket": t2, "code": codes[0]}))
        seen.append(await c.get("/api/auth/me", headers=auth))
        seen.append(await c.get("/api/auth/sessions", headers=auth))
        seen.append(await c.post("/api/auth/refresh", headers={"X-CVEnom-CSRF": "1"}))
        a = await full_login(c, "a@example.com", PW, secret=admin_secret)
        aauth = {"Authorization": f"Bearer {a.json()['access_token']}"}
        seen.append(await c.get("/api/auth/users", headers=aauth))
    assert seen[1].status_code == 401
    assert seen[2].status_code == 200
    enc = db_session.scalars(select(User).where(User.email == EMAIL)).one().mfa_secret_enc
    for r in seen:
        assert secret not in r.text and enc not in r.text
        assert "mfa_secret" not in r.text
    # nothing secret ever reaches the logs
    for needle in [secret, enc, t, t2, *codes]:
        assert needle not in caplog.text


# ---------------------------------------------------------------- recovery codes


async def test_recovery_code_works_once(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        fin = await full_login(c, EMAIL, PW)
        codes = fin.json()["recovery_codes"]
        t = (await ticket_for(c))["ticket"]
        # case and separators are forgiven
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t, "code": f"  {codes[3].upper()}  "})
        assert r.status_code == 200 and "access_token" in r.json()
        t2 = (await ticket_for(c))["ticket"]
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t2, "code": codes[3]})
        assert r.status_code == 401 and r.json() == FAIL
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t2, "code": codes[4].replace("-", "")})
        assert r.status_code == 200
    rows = db_session.scalars(select(MfaRecoveryCode)).all()
    assert sum(1 for x in rows if x.used_at is not None) == 2


async def test_recovery_code_of_another_user_rejected(db_session):
    mk_user(db_session, "a@example.com")
    mk_user(db_session, "b@example.com")
    async with client(make_app(db_session)) as c:
        await full_login(c, "a@example.com", PW)
        codes_b = (await full_login(c, "b@example.com", PW)).json()["recovery_codes"]
        t = (await ticket_for(c, "a@example.com"))["ticket"]
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t, "code": codes_b[0]})
    assert r.status_code == 401


# ---------------------------------------------------------------- invites


async def test_invite_accept_issues_no_session_and_leads_to_enrollment(db_session):
    admin = mk_user(db_session, "a@example.com", "admin")
    raw = create_invite(db_session, admin, "new@example.com", "member")
    async with client(make_app(db_session)) as c:
        r = await c.post("/api/auth/invites/accept", json={"token": raw, "password": PW})
        assert r.status_code == 201
        assert_no_session(r)
        body = r.json()
        assert set(body) == {"id", "email", "role", "ticket", "enroll_required", "expires_in"}
        assert body["enroll_required"] is True
        assert db_session.scalars(select(UserSession)).all() == []
        # the ticket only enrolls: verify cannot skip it
        v = await c.post("/api/auth/mfa/verify", json={"ticket": body["ticket"], "code": "123456"})
        assert v.status_code == 401
        s = await c.post("/api/auth/mfa/enroll/start", json={"ticket": body["ticket"]})
        f = await c.post("/api/auth/mfa/enroll/finish",
                         json={"ticket": body["ticket"], "code": code_for(s.json()["secret"])})
    assert f.status_code == 200 and len(f.json()["recovery_codes"]) == 10
    assert db_session.scalars(select(User).where(User.email == "new@example.com")
                              ).one().mfa_enabled_at is not None


async def test_password_reset_does_not_touch_mfa(db_session):
    admin = mk_user(db_session, "a@example.com", "admin")
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    enc = u.mfa_secret_enc
    raw = create_invite(db_session, admin, EMAIL, "member", 24, purpose="reset")
    async with client(make_app(db_session)) as c:
        r = await c.post("/api/auth/invites/accept",
                         json={"token": raw, "password": "a brand new passphrase"})
        assert r.status_code == 201
        assert_no_session(r)
        assert r.json()["enroll_required"] is False
        v = await c.post("/api/auth/mfa/verify",
                         json={"ticket": r.json()["ticket"], "code": code_for(secret)})
        assert v.status_code == 200
    assert db_session.get(User, u.id).mfa_secret_enc == enc


# ---------------------------------------------------------------- validation / plumbing


async def test_body_validation(db_session):
    async with client(make_app(db_session)) as c:
        r = await c.post("/api/auth/mfa/verify", json={"ticket": "t" * 300, "code": "123456"})
        assert r.status_code == 422
        r = await c.post("/api/auth/mfa/verify", json={"ticket": "t", "code": "1" * 100})
        assert r.status_code == 422
        r = await c.post("/api/auth/mfa/verify",
                         json={"ticket": "t", "code": "123456", "user_id": 1})
        assert r.status_code == 422
        r = await c.post("/api/auth/mfa/enroll/start", json={"ticket": "t", "secret": "x"})
        assert r.status_code == 422
        r = await c.post("/api/auth/mfa/enroll/finish", json={"ticket": "t"})
        assert r.status_code == 422


async def test_responses_are_no_store(db_session):
    mk_user(db_session)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]
        s = await c.post("/api/auth/mfa/enroll/start", json={"ticket": t})
    assert s.headers["cache-control"] == "no-store"
    assert s.headers["referrer-policy"] == "no-referrer"


async def test_failed_commit_verify_is_500_without_cookie(db_session):
    u = mk_user(db_session)
    secret = enroll_user(db_session, u)
    async with client(make_app(db_session)) as c:
        t = (await ticket_for(c))["ticket"]

    @contextmanager
    def failing():
        yield db_session
        raise RuntimeError("commit failed")

    app = create_app(get_settings(), redis=fakeredis.FakeAsyncRedis(), session_factory=failing)
    async with client(app) as c:
        r = await c.post("/api/auth/mfa/verify", json={"ticket": t, "code": code_for(secret)})
    assert r.status_code == 500 and "set-cookie" not in r.headers


async def test_expired_tickets_are_swept_on_issue(db_session):
    u = mk_user(db_session)
    db_session.add(MfaTicket(token_hash="x" * 64, user_id=u.id,
                             expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db_session.flush()
    async with client(make_app(db_session)) as c:
        await ticket_for(c)
    hashes = [r.token_hash for r in db_session.scalars(select(MfaTicket))]
    assert "x" * 64 not in hashes and len(hashes) == 1
