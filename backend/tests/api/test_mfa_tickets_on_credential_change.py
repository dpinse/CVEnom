"""Review fix 1: a pending MFA ticket dies whenever the user's sessions are revoked or
their password changes (reset, change, admin revoke, deactivation)."""

import base64
import os
from contextlib import contextmanager
from datetime import UTC, datetime

import fakeredis
import httpx
import pytest
from mfa_helpers import code_for, enroll_user
from sqlalchemy import select

from cvenom.api import create_app
from cvenom.auth.passwords import hash_password
from cvenom.auth.tokens import create_session, issue_access
from cvenom.config import get_settings
from cvenom.models import MfaTicket, User

PW = "correct horse battery"
NEW_PW = "another long passphrase"
FAIL = {"error": "invalid_mfa"}


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_app(db):
    @contextmanager
    def factory():
        yield db

    return create_app(get_settings(), redis=fakeredis.FakeAsyncRedis(), session_factory=factory)


def client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=("1.2.3.4", 1234)), base_url="https://test"
    )


def mk(db, email, role="member"):
    u = User(email=email, password_hash=hash_password(PW), role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def bearer(db, user):
    now = datetime.now(UTC)
    row, _ = create_session(db, user, now, "ua", None)
    return {"Authorization": f"Bearer {issue_access(db, user, row.id, now)}"}, row


async def pending(c, email):
    r = await c.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200
    return r.json()["ticket"]


def tickets_of(db, user):
    return db.scalars(select(MfaTicket).where(MfaTicket.user_id == user.id)).all()


async def test_password_reset_kills_a_pending_enrollment_ticket(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    victim = mk(db_session, "v@example.com")  # not enrolled yet
    ah, _ = bearer(db_session, admin)
    async with client(make_app(db_session)) as c:
        old = await pending(c, "v@example.com")
        s = await c.post("/api/auth/mfa/enroll/start", json={"ticket": old})
        assert s.status_code == 200
        reset = await c.post(f"/api/auth/users/{victim.id}/reset", headers=ah)
        acc = await c.post("/api/auth/invites/accept",
                           json={"token": reset.json()["token"], "password": NEW_PW})
        assert acc.status_code == 201
        fin = await c.post("/api/auth/mfa/enroll/finish",
                           json={"ticket": old, "code": code_for(s.json()["secret"])})
        assert fin.status_code == 401 and fin.json() == FAIL
        ver = await c.post("/api/auth/mfa/verify", json={"ticket": old, "code": "123456"})
        assert ver.status_code == 401 and ver.json() == FAIL
        st = await c.post("/api/auth/mfa/enroll/start", json={"ticket": old})
        assert st.status_code == 401
    # only the ticket the reset itself issued remains
    hashes = [t.token_hash for t in tickets_of(db_session, victim)]
    assert len(hashes) == 1
    assert db_session.get(User, victim.id).mfa_enabled_at is None


async def test_password_reset_kills_a_pending_verify_ticket_of_an_enrolled_user(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    victim = mk(db_session, "v@example.com")
    secret = enroll_user(db_session, victim)
    ah, _ = bearer(db_session, admin)
    async with client(make_app(db_session)) as c:
        old = await pending(c, "v@example.com")
        reset = await c.post(f"/api/auth/users/{victim.id}/reset", headers=ah)
        await c.post("/api/auth/invites/accept",
                     json={"token": reset.json()["token"], "password": NEW_PW})
        ver = await c.post("/api/auth/mfa/verify", json={"ticket": old, "code": code_for(secret)})
    assert ver.status_code == 401 and ver.json() == FAIL


async def test_password_change_kills_pending_tickets(db_session):
    u = mk(db_session, "u@example.com")
    secret = enroll_user(db_session, u)
    uh, _ = bearer(db_session, u)
    async with client(make_app(db_session)) as c:
        old = await pending(c, "u@example.com")
        r = await c.post("/api/auth/password",
                         json={"current_password": PW, "new_password": NEW_PW}, headers=uh)
        assert r.status_code == 204
        ver = await c.post("/api/auth/mfa/verify", json={"ticket": old, "code": code_for(secret)})
    assert ver.status_code == 401
    assert tickets_of(db_session, u) == []


async def test_admin_revoke_sessions_kills_pending_tickets(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    u = mk(db_session, "u@example.com")
    secret = enroll_user(db_session, u)
    ah, _ = bearer(db_session, admin)
    async with client(make_app(db_session)) as c:
        old = await pending(c, "u@example.com")
        r = await c.post(f"/api/auth/users/{u.id}/sessions/revoke", headers=ah)
        assert r.status_code == 204
        ver = await c.post("/api/auth/mfa/verify", json={"ticket": old, "code": code_for(secret)})
    assert ver.status_code == 401
    assert tickets_of(db_session, u) == []


async def test_deactivation_kills_pending_tickets(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    u = mk(db_session, "u@example.com")
    ah, _ = bearer(db_session, admin)
    async with client(make_app(db_session)) as c:
        await pending(c, "u@example.com")
        r = await c.patch(f"/api/auth/users/{u.id}", json={"is_active": False}, headers=ah)
        assert r.status_code == 200
    assert tickets_of(db_session, u) == []


def test_revoke_sessions_drops_tickets_and_keeps_other_users(db_session):
    from cvenom.auth.mfa import issue_ticket
    from cvenom.auth.users import revoke_sessions

    a = mk(db_session, "a@example.com")
    b = mk(db_session, "b@example.com")
    now = datetime.now(UTC)
    issue_ticket(db_session, a, now)
    issue_ticket(db_session, b, now)
    revoke_sessions(db_session, a.id, now)
    db_session.flush()
    assert tickets_of(db_session, a) == []
    assert len(tickets_of(db_session, b)) == 1

