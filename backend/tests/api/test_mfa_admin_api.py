"""MFA account endpoint (status, recovery codes) and the admin MFA reset."""

import base64
import os
from contextlib import contextmanager
from datetime import UTC, datetime

import fakeredis
import httpx
import pytest
from mfa_helpers import code_for, full_login
from sqlalchemy import select

from cvenom.api import create_app
from cvenom.auth.passwords import hash_password
from cvenom.auth.tokens import create_session
from cvenom.config import get_settings
from cvenom.models import MfaRecoveryCode, MfaTicket, User, UserSession

PW = "correct horse battery"


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_app(db, **overrides):
    settings = get_settings().model_copy(update=overrides)

    @contextmanager
    def factory():
        yield db

    return create_app(settings, redis=fakeredis.FakeAsyncRedis(), session_factory=factory)


def client(app, peer=("1.2.3.4", 1234)):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=peer), base_url="https://test"
    )


def mk(db, email, role="member"):
    u = User(email=email, password_hash=hash_password(PW), role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def bearer_of(r):
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def frozen(monkeypatch):
    from cvenom.api import routes_mfa

    base = (int(datetime.now(UTC).timestamp()) // 30) * 30 + 15
    state = {"t": base}
    monkeypatch.setattr(routes_mfa, "_now", lambda: datetime.fromtimestamp(state["t"], UTC))

    class Clock:
        t0 = base

        def set(self, t):
            state["t"] = t

    return Clock()


async def enroll_via_api(c, email, at=None):
    """Enroll through the real endpoints; returns (final response, base32 secret)."""
    t = (await c.post("/api/auth/login", json={"email": email, "password": PW})).json()["ticket"]
    s = (await c.post("/api/auth/mfa/enroll/start", json={"ticket": t})).json()["secret"]
    r = await c.post("/api/auth/mfa/enroll/finish", json={"ticket": t, "code": code_for(s, at)})
    assert r.status_code == 200
    return r, s


# ---------------------------------------------------------------- account status


async def test_status_shows_enrollment_and_remaining_codes(db_session):
    mk(db_session, "u@example.com")
    async with client(make_app(db_session)) as c:
        fin, secret = await enroll_via_api(c, "u@example.com")
        auth = bearer_of(fin)
        r = await c.get("/api/auth/mfa", headers=auth)
        assert r.status_code == 200
        body = r.json()
        assert set(body) == {"enabled", "enrolled_at", "recovery_codes_remaining"}
        assert body["enabled"] is True and body["recovery_codes_remaining"] == 10
        assert secret not in r.text
        # spend one recovery code at sign-in: the count drops
        t = (await c.post("/api/auth/login",
                          json={"email": "u@example.com", "password": PW})).json()["ticket"]
        v = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t, "code": fin.json()["recovery_codes"][0]})
        assert v.status_code == 200
        r = await c.get("/api/auth/mfa", headers=auth)
        assert r.json()["recovery_codes_remaining"] == 9


async def test_status_requires_auth(db_session):
    async with client(make_app(db_session)) as c:
        assert (await c.get("/api/auth/mfa")).status_code == 401
        r = await c.post("/api/auth/mfa/recovery-codes", json={"code": "123456"})
        assert r.status_code == 401


# ---------------------------------------------------------------- regenerate


async def test_regenerate_needs_a_current_totp_and_kills_old_codes(db_session, frozen):
    mk(db_session, "u@example.com")
    async with client(make_app(db_session)) as c:
        fin, secret = await enroll_via_api(c, "u@example.com", at=frozen.t0)
        old = fin.json()["recovery_codes"]
        auth = bearer_of(fin)
        # the step used to enroll is spent; a recovery code is not accepted here
        bad = await c.post("/api/auth/mfa/recovery-codes", json={"code": old[0]},
                           headers=auth)
        assert bad.status_code == 403 and bad.json() == {"error": "invalid_code"}
        replay = await c.post("/api/auth/mfa/recovery-codes",
                              json={"code": code_for(secret, frozen.t0)}, headers=auth)
        assert replay.status_code == 403
        ok = await c.post("/api/auth/mfa/recovery-codes",
                          json={"code": code_for(secret, frozen.t0 + 30)}, headers=auth)
        assert ok.status_code == 200
        new = ok.json()["recovery_codes"]
        assert set(ok.json()) == {"recovery_codes"}
        assert len(new) == 10 and not (set(new) & set(old))
        assert secret not in ok.text
        # old codes are dead, new ones work
        t = (await c.post("/api/auth/login",
                          json={"email": "u@example.com", "password": PW})).json()["ticket"]
        assert (await c.post("/api/auth/mfa/verify",
                             json={"ticket": t, "code": old[1]})).status_code == 401
        assert (await c.post("/api/auth/mfa/verify",
                             json={"ticket": t, "code": new[1]})).status_code == 200
    assert len(db_session.scalars(select(MfaRecoveryCode)).all()) == 10


async def test_regenerate_is_rate_limited(db_session):
    mk(db_session, "u@example.com")
    async with client(make_app(db_session)) as c:
        fin, _secret = await enroll_via_api(c, "u@example.com")
        auth = bearer_of(fin)
        codes = [
            (await c.post("/api/auth/mfa/recovery-codes", json={"code": "zzzzzz"},
                          headers=auth)).status_code
            for _ in range(6)
        ]
    assert codes == [403] * 5 + [429]


async def test_regenerate_body_validation(db_session):
    mk(db_session, "u@example.com")
    async with client(make_app(db_session)) as c:
        fin, _ = await enroll_via_api(c, "u@example.com")
        r = await c.post("/api/auth/mfa/recovery-codes", json={"code": "1" * 100},
                         headers=bearer_of(fin))
        assert r.status_code == 422


# ---------------------------------------------------------------- admin reset


@pytest.fixture
def pair(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    member = mk(db_session, "m@example.com")
    return admin, member


async def test_admin_reset_revokes_sessions_and_forces_reenrollment(db_session, pair):
    admin, member = pair
    async with client(make_app(db_session)) as c:
        afin, _ = await enroll_via_api(c, "a@example.com")
        mfin, msecret = await enroll_via_api(c, "m@example.com")
        old_codes = mfin.json()["recovery_codes"]
        mauth = bearer_of(mfin)
        # a second live session and an outstanding ticket for the member
        now = datetime.now(UTC)
        other, _ = create_session(db_session, member, now, "ua", None)
        pending = (await c.post("/api/auth/login",
                                json={"email": "m@example.com", "password": PW})).json()
        assert (await c.get("/api/auth/me", headers=mauth)).status_code == 200

        r = await c.post(f"/api/auth/users/{member.id}/mfa/reset", headers=bearer_of(afin))
        assert r.status_code == 204

        assert (await c.get("/api/auth/me", headers=mauth)).status_code == 401
        sessions = db_session.scalars(
            select(UserSession).where(UserSession.user_id == member.id)).all()
        assert sessions and all(s.revoked_at is not None for s in sessions)
        m = db_session.get(User, member.id)
        assert m.mfa_secret_enc is None and m.mfa_enabled_at is None and m.mfa_last_step is None
        assert db_session.scalars(select(MfaRecoveryCode).where(
            MfaRecoveryCode.user_id == member.id)).all() == []
        assert db_session.scalars(select(MfaTicket).where(
            MfaTicket.user_id == member.id)).all() == []
        # the outstanding ticket died with the reset
        v = await c.post("/api/auth/mfa/verify",
                         json={"ticket": pending["ticket"], "code": old_codes[0]})
        assert v.status_code == 401
        # next sign-in must enroll again
        t = (await c.post("/api/auth/login",
                          json={"email": "m@example.com", "password": PW})).json()
        assert t["enroll_required"] is True
        v = await c.post("/api/auth/mfa/verify",
                         json={"ticket": t["ticket"], "code": code_for(msecret)})
        assert v.status_code == 401
        again = await full_login(c, "m@example.com", PW)
        assert again.status_code == 200 and len(again.json()["recovery_codes"]) == 10
    # the admin's own session is untouched
    assert db_session.get(User, admin.id).mfa_enabled_at is not None
    assert other.revoked_at is not None


async def test_admin_cannot_reset_own_mfa(db_session, pair):
    admin, _ = pair
    async with client(make_app(db_session)) as c:
        afin, _ = await enroll_via_api(c, "a@example.com")
        r = await c.post(f"/api/auth/users/{admin.id}/mfa/reset", headers=bearer_of(afin))
        assert r.status_code == 409 and r.json() == {"error": "cannot_modify_self"}
        assert (await c.get("/api/auth/me", headers=bearer_of(afin))).status_code == 200
    assert db_session.get(User, admin.id).mfa_enabled_at is not None


async def test_member_cannot_reset_mfa(db_session, pair):
    admin, member = pair
    async with client(make_app(db_session)) as c:
        await enroll_via_api(c, "a@example.com")
        mfin, _ = await enroll_via_api(c, "m@example.com")
        r = await c.post(f"/api/auth/users/{admin.id}/mfa/reset", headers=bearer_of(mfin))
        assert r.status_code == 403
        assert (await c.post(f"/api/auth/users/{admin.id}/mfa/reset")).status_code == 401
    assert db_session.get(User, admin.id).mfa_enabled_at is not None


async def test_admin_reset_unknown_user_404(db_session, pair):
    async with client(make_app(db_session)) as c:
        afin, _ = await enroll_via_api(c, "a@example.com")
        for uid in ("999999", "99999999999"):
            r = await c.post(f"/api/auth/users/{uid}/mfa/reset", headers=bearer_of(afin))
            assert r.status_code == 404


async def test_user_list_shows_mfa_status_but_no_secret(db_session, pair):
    admin, member = pair
    async with client(make_app(db_session)) as c:
        afin, secret = await enroll_via_api(c, "a@example.com")
        r = await c.get("/api/auth/users", headers=bearer_of(afin))
    rows = {u["email"]: u for u in r.json()}
    assert rows["a@example.com"]["mfa_enabled"] is True
    assert rows["m@example.com"]["mfa_enabled"] is False
    assert secret not in r.text and "v1:" not in r.text


# ---------------------------------------------------------------- CLI


def _factory(session):
    @contextmanager
    def scope():
        yield session

    return scope


def test_cli_reset_mfa(db_session, capsys):
    from cvenom import cli

    u = mk(db_session, "boss@example.com", "admin")
    u.mfa_secret_enc = "v1:x"
    u.mfa_enabled_at = datetime.now(UTC)
    u.mfa_last_step = 5
    db_session.add(MfaRecoveryCode(user_id=u.id, code_hash="h" * 64))
    row, _ = create_session(db_session, u, datetime.now(UTC), "ua", None)
    db_session.flush()
    rc = cli.main(["reset-mfa", "--email", " Boss@Example.com "],
                  session_factory=_factory(db_session))
    out = capsys.readouterr().out
    assert rc == 0
    assert "boss@example.com" in out and "v1:" not in out
    db_session.refresh(u)
    assert u.mfa_secret_enc is None and u.mfa_enabled_at is None and u.mfa_last_step is None
    assert db_session.scalars(select(MfaRecoveryCode)).all() == []
    db_session.refresh(row)
    assert row.revoked_at is not None


def test_cli_reset_mfa_unknown_email_exit_1(db_session, capsys):
    from cvenom import cli

    rc = cli.main(["reset-mfa", "--email", "nobody@example.com"],
                  session_factory=_factory(db_session))
    cap = capsys.readouterr()
    assert rc == 1 and cap.out == "" and "no such user" in cap.err


def test_cli_reset_mfa_reads_no_password(db_session, monkeypatch):
    from cvenom import cli

    mk(db_session, "x@example.com")

    def boom():
        raise AssertionError("reset-mfa must not prompt for a password")

    monkeypatch.setattr(cli, "_read_password", boom)
    assert cli.main(["reset-mfa", "--email", "x@example.com"],
                    session_factory=_factory(db_session)) == 0


def test_create_admin_still_unchanged_and_unenrolled(db_session, monkeypatch):
    from cvenom import cli

    monkeypatch.setenv("ADMIN_PASSWORD", "a long admin passphrase")
    assert cli.main(["create-admin", "--email", "root@example.com"],
                    session_factory=_factory(db_session)) == 0
    u = db_session.scalars(select(User)).one()
    assert u.mfa_enabled_at is None  # enrolls at first sign-in

