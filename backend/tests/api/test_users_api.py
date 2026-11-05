"""Task 15: user administration, password change/reset, invite administration."""

import base64
import os
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import fakeredis
import httpx
import pytest
from sqlalchemy import event, select

from cvenom.api import create_app
from cvenom.auth.passwords import hash_password, verify_password
from cvenom.auth.tokens import create_session, issue_access
from cvenom.auth.users import (
    InvalidInvite,
    LastAdmin,
    accept_invite,
    create_invite,
    update_user,
)
from cvenom.config import get_settings
from cvenom.models import Invite, User
from mfa_helpers import full_login

PW = "correct horse battery"
NEW_PW = "another long passphrase"
CSRF = {"X-CVEnom-CSRF": "1"}


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


def mk(db, email, role="member", active=True):
    u = User(email=email, password_hash=hash_password(PW), role=role, is_active=active)
    db.add(u)
    db.flush()
    return u


def sess(db, user):
    now = datetime.now(UTC)
    row, raw = create_session(db, user, now, "ua", "9.9.9.9")
    return {"Authorization": f"Bearer {issue_access(db, user, row.id, now)}"}, row, raw


@pytest.fixture
def ctx(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    member = mk(db_session, "m@example.com")
    ah, arow, _ = sess(db_session, admin)
    mh, mrow, _ = sess(db_session, member)
    return {
        "app": make_app(db_session), "db": db_session, "admin": admin, "member": member,
        "ah": ah, "mh": mh, "arow": arow, "mrow": mrow,
    }


# ------------------------------------------------------------ authz


async def test_member_forbidden_on_every_admin_route(ctx):
    mh, mid = ctx["mh"], ctx["member"].id
    calls = [
        ("GET", "/api/auth/users", None),
        ("PATCH", f"/api/auth/users/{mid}", {"role": "admin"}),
        ("POST", f"/api/auth/users/{mid}/sessions/revoke", None),
        ("POST", f"/api/auth/users/{mid}/reset", None),
        ("GET", "/api/auth/invites", None),
        ("DELETE", "/api/auth/invites/1", None),
    ]
    async with client(ctx["app"]) as c:
        for method, path, body in calls:
            r = await c.request(method, path, json=body, headers=mh)
            assert r.status_code == 403, path
            assert r.json() == {"error": "forbidden"}
            r = await c.request(method, path, json=body)
            assert r.status_code == 401, path
    assert ctx["member"].role == "member"


# ------------------------------------------------------------ list


async def test_list_users_shape_and_active_sessions(ctx):
    db, member = ctx["db"], ctx["member"]
    now = datetime.now(UTC)
    sess(db, member)  # second live session
    revoked = sess(db, member)[1]
    revoked.revoked_at = now
    expired = sess(db, member)[1]
    expired.expires_at = now - timedelta(minutes=1)
    db.flush()
    async with client(ctx["app"]) as c:
        r = await c.get("/api/auth/users", headers=ctx["ah"])
    assert r.status_code == 200
    rows = {u["email"]: u for u in r.json()}
    assert set(rows["m@example.com"]) == {
        "id", "email", "role", "is_active", "created_at", "active_sessions"}
    assert rows["m@example.com"]["active_sessions"] == 2
    assert rows["a@example.com"]["active_sessions"] == 1
    assert "password" not in r.text


# ------------------------------------------------------------ patch


async def test_deactivate_revokes_sessions_and_tokens_die(ctx):
    db, member = ctx["db"], ctx["member"]
    other_row = sess(db, member)[1]
    async with client(ctx["app"]) as c:
        assert (await c.get("/api/auth/me", headers=ctx["mh"])).status_code == 200
        r = await c.patch(f"/api/auth/users/{member.id}", json={"is_active": False},
                          headers=ctx["ah"])
        assert r.status_code == 200
        assert r.json()["is_active"] is False
        assert (await c.get("/api/auth/me", headers=ctx["mh"])).status_code == 401
    db.refresh(ctx["mrow"])
    db.refresh(other_row)
    assert ctx["mrow"].revoked_at is not None and other_row.revoked_at is not None
    assert db.get(User, member.id).is_active is False


async def test_deactivated_users_refresh_token_fails(ctx):
    async with client(ctx["app"]) as c:
        r = await full_login(c, "m@example.com", PW)
        assert r.status_code == 200
        cookie = r.headers["set-cookie"].split(";", 1)[0]
        await c.patch(f"/api/auth/users/{ctx['member'].id}", json={"is_active": False},
                      headers=ctx["ah"])
        r = await c.post("/api/auth/refresh", headers={**CSRF, "Cookie": cookie})
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_token"}


async def test_role_change_and_reactivate(ctx):
    mid = ctx["member"].id
    async with client(ctx["app"]) as c:
        r = await c.patch(f"/api/auth/users/{mid}", json={"role": "admin"}, headers=ctx["ah"])
        assert r.status_code == 200 and r.json()["role"] == "admin"
        r = await c.patch(f"/api/auth/users/{mid}", json={"is_active": False}, headers=ctx["ah"])
        assert r.status_code == 200
        r = await c.patch(f"/api/auth/users/{mid}", json={"is_active": True}, headers=ctx["ah"])
        assert r.status_code == 200 and r.json()["is_active"] is True


@pytest.mark.parametrize("body", [{"role": "member"}, {"is_active": False}])
async def test_admin_cannot_modify_self(ctx, body):
    aid = ctx["admin"].id
    async with client(ctx["app"]) as c:
        r = await c.patch(f"/api/auth/users/{aid}", json=body, headers=ctx["ah"])
    assert r.status_code == 409
    assert r.json() == {"error": "cannot_modify_self"}
    u = ctx["db"].get(User, aid)
    assert u.role == "admin" and u.is_active is True


async def test_last_admin_cannot_be_demoted_or_deactivated(ctx):
    db, admin = ctx["db"], ctx["admin"]
    # An HTTP caller is always itself an active admin, so drive the guard directly.
    with pytest.raises(LastAdmin):
        update_user(db, admin, role="member")
    with pytest.raises(LastAdmin):
        update_user(db, admin, is_active=False)
    assert admin.role == "admin" and admin.is_active
    second = mk(db, "a2@example.com", "admin")
    update_user(db, second, role="member")  # two admins: fine
    assert second.role == "member"
    with pytest.raises(LastAdmin):
        update_user(db, admin, is_active=False)


async def test_last_admin_check_locks_admin_rows(ctx):
    db = ctx["db"]
    second = mk(db, "a2@example.com", "admin")
    statements = []

    def spy(conn, cursor, statement, *a):
        statements.append(statement)

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", spy)
    try:
        async with client(ctx["app"]) as c:
            r = await c.patch(f"/api/auth/users/{second.id}", json={"role": "member"},
                              headers=ctx["ah"])
    finally:
        event.remove(engine, "before_cursor_execute", spy)
    assert r.status_code == 200
    locking = [s for s in statements if "FOR UPDATE" in s and "app_user" in s]
    assert locking, statements
    assert "ORDER BY" in locking[0]  # deterministic lock order avoids deadlocks


async def test_patch_unknown_user_and_bad_bodies(ctx):
    async with client(ctx["app"]) as c:
        h = ctx["ah"]
        assert (await c.patch("/api/auth/users/999999", json={"is_active": False},
                              headers=h)).status_code == 404
        assert (await c.patch("/api/auth/users/99999999999", json={"is_active": False},
                              headers=h)).status_code == 404
        mid = ctx["member"].id
        for body in ({"role": "root"}, {"extra": 1}, {"role": None}, {"is_active": None}):
            r = await c.patch(f"/api/auth/users/{mid}", json=body, headers=h)
            assert r.status_code == 422, body
    assert ctx["db"].get(User, mid).role == "member"


async def test_revoke_all_sessions(ctx):
    db, member = ctx["db"], ctx["member"]
    async with client(ctx["app"]) as c:
        r = await c.post(f"/api/auth/users/{member.id}/sessions/revoke", headers=ctx["ah"])
        assert r.status_code == 204
        assert (await c.get("/api/auth/me", headers=ctx["mh"])).status_code == 401
        assert (await c.post("/api/auth/users/999999/sessions/revoke",
                             headers=ctx["ah"])).status_code == 404
    assert db.get(User, member.id).is_active is True


# ------------------------------------------------------------ own password


async def test_password_change_revokes_other_sessions_keeps_current(ctx):
    db, member = ctx["db"], ctx["member"]
    _, other, _ = sess(db, member)
    async with client(ctx["app"]) as c:
        r = await c.post("/api/auth/password",
                         json={"current_password": PW, "new_password": NEW_PW},
                         headers=ctx["mh"])
        assert r.status_code == 204
        assert (await c.get("/api/auth/me", headers=ctx["mh"])).status_code == 200
    db.refresh(other)
    db.refresh(ctx["mrow"])
    assert other.revoked_at is not None
    assert ctx["mrow"].revoked_at is None
    u = db.get(User, member.id)
    assert verify_password(u.password_hash, NEW_PW)
    assert not verify_password(u.password_hash, PW)


async def test_password_change_wrong_current_is_generic_401(ctx):
    async with client(ctx["app"]) as c:
        r = await c.post("/api/auth/password",
                         json={"current_password": "wrong wrong wrong", "new_password": NEW_PW},
                         headers=ctx["mh"])
    assert r.status_code == 401
    assert r.json() == {"error": "invalid_credentials"}
    assert verify_password(ctx["db"].get(User, ctx["member"].id).password_hash, PW)


@pytest.mark.parametrize("new", ["short", " " * 20, "x" * 300])
async def test_password_change_weak_new_is_422(ctx, new):
    async with client(ctx["app"]) as c:
        r = await c.post("/api/auth/password",
                         json={"current_password": PW, "new_password": new}, headers=ctx["mh"])
    assert r.status_code == 422
    assert r.json() == {"error": "weak_password"}
    assert verify_password(ctx["db"].get(User, ctx["member"].id).password_hash, PW)


async def test_password_change_requires_auth_forbids_extra_and_is_rate_limited(ctx):
    async with client(ctx["app"]) as c:
        body = {"current_password": PW, "new_password": NEW_PW}
        assert (await c.post("/api/auth/password", json=body)).status_code == 401
        r = await c.post("/api/auth/password", json={**body, "x": 1}, headers=ctx["mh"])
        assert r.status_code == 422
        statuses = []
        for _ in range(12):
            r = await c.post("/api/auth/password",
                             json={"current_password": "nope nope nope nope",
                                   "new_password": NEW_PW}, headers=ctx["mh"])
            statuses.append(r.status_code)
    assert statuses[0] == 401
    assert 429 in statuses  # enforce_login_limits keyed on the email


# ------------------------------------------------------------ reset


async def test_admin_reset_flow_single_use_sets_password_and_revokes(ctx):
    db, member = ctx["db"], ctx["member"]
    async with client(ctx["app"]) as c:
        r = await c.post(f"/api/auth/users/{member.id}/reset", headers=ctx["ah"])
        assert r.status_code == 201
        body = r.json()
        assert set(body) == {"token", "expires_at"}
        inv = db.scalars(select(Invite).where(Invite.purpose == "reset")).one()
        assert inv.email == "m@example.com" and inv.role == "member"
        assert inv.token_hash != body["token"]
        ttl = inv.expires_at - datetime.now(UTC)
        assert timedelta(hours=23) < ttl <= timedelta(hours=24, seconds=5)

        r = await c.post("/api/auth/invites/accept",
                         json={"token": body["token"], "password": NEW_PW})
        assert r.status_code == 201
        acc = r.json()
        assert {k: acc[k] for k in ("id", "email", "role")} == {
            "id": member.id, "email": "m@example.com", "role": "member"}
        assert "set-cookie" not in r.headers and "access_token" not in r.text
        # single use
        r = await c.post("/api/auth/invites/accept",
                         json={"token": body["token"], "password": "yet another passphrase"})
        assert r.status_code == 400 and r.json() == {"error": "invalid_invite"}
        assert (await c.get("/api/auth/me", headers=ctx["mh"])).status_code == 401
        r = await full_login(c, "m@example.com", NEW_PW)
        assert r.status_code == 200
    assert db.scalars(select(User).where(User.email == "m@example.com")).one().id == member.id
    assert len(db.scalars(select(User)).all()) == 2  # no account created


async def test_reset_weak_password_does_not_consume_token(ctx):
    db, member = ctx["db"], ctx["member"]
    raw = create_invite(db, ctx["admin"], member.email, "member", 24, purpose="reset")
    async with client(ctx["app"]) as c:
        r = await c.post("/api/auth/invites/accept", json={"token": raw, "password": "short"})
        assert r.status_code == 422
        r = await c.post("/api/auth/invites/accept", json={"token": raw, "password": NEW_PW})
        assert r.status_code == 201


async def test_reset_for_inactive_user_is_409(ctx):
    db = ctx["db"]
    dead = mk(db, "dead@example.com", active=False)
    async with client(ctx["app"]) as c:
        r = await c.post(f"/api/auth/users/{dead.id}/reset", headers=ctx["ah"])
        assert r.status_code == 409 and r.json() == {"error": "user_inactive"}
        assert (await c.post("/api/auth/users/999999/reset",
                             headers=ctx["ah"])).status_code == 404
    assert db.scalars(select(Invite)).all() == []


def test_reset_token_cannot_create_account(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    raw = create_invite(db_session, admin, "ghost@example.com", "member", 24, purpose="reset")
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, raw, PW)
    assert db_session.scalars(select(User).where(User.email == "ghost@example.com")).first() is None


def test_reset_token_for_deactivated_user_is_invalid(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    victim = mk(db_session, "v@example.com")
    raw = create_invite(db_session, admin, victim.email, "member", 24, purpose="reset")
    victim.is_active = False
    db_session.flush()
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, raw, NEW_PW)
    assert verify_password(victim.password_hash, PW)


def test_plain_invite_cannot_reset_existing_user(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    victim = mk(db_session, "v@example.com")
    raw = create_invite(db_session, admin, victim.email, "member")
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, raw, NEW_PW)
    assert verify_password(victim.password_hash, PW)


def test_expired_reset_token_is_invalid(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    victim = mk(db_session, "v@example.com")
    raw = create_invite(db_session, admin, victim.email, "member", 24, purpose="reset")
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, raw, NEW_PW, now=datetime.now(UTC) + timedelta(hours=25))


def test_normal_invite_flow_unchanged(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    raw = create_invite(db_session, admin, "New@Example.com", "member")
    user = accept_invite(db_session, raw, PW)
    assert user.email == "new@example.com"
    assert db_session.scalars(select(Invite)).one().purpose == "invite"


# ------------------------------------------------------------ invites admin


async def test_invite_list_has_no_secrets_and_only_pending(ctx):
    db, admin = ctx["db"], ctx["admin"]
    now = datetime.now(UTC)
    raw = create_invite(db, admin, "p1@example.com", "member", now=now)
    create_invite(db, admin, "gone@example.com", "member", now=now - timedelta(days=10))
    used_raw = create_invite(db, admin, "used@example.com", "member", now=now)
    accept_invite(db, used_raw, PW)
    reset_raw = create_invite(db, admin, "m@example.com", "member", 24, purpose="reset")
    async with client(ctx["app"]) as c:
        r = await c.get("/api/auth/invites", headers=ctx["ah"])
    assert r.status_code == 200
    items = r.json()
    assert {i["email"] for i in items} == {"p1@example.com", "m@example.com"}
    for i in items:
        assert set(i) == {"id", "email", "role", "purpose", "expires_at", "created_at",
                          "created_by"}
        assert {i["created_by"] for i in items} == {admin.id}
    assert {i["purpose"] for i in items} == {"invite", "reset"}
    hashes = [x.token_hash for x in db.scalars(select(Invite))]
    for secret in [raw, reset_raw, used_raw, *hashes]:
        assert secret not in r.text


async def test_delete_invite_revokes_it(ctx):
    db, admin = ctx["db"], ctx["admin"]
    raw = create_invite(db, admin, "p1@example.com", "member")
    inv = db.scalars(select(Invite)).one()
    async with client(ctx["app"]) as c:
        assert (await c.delete(f"/api/auth/invites/{inv.id}", headers=ctx["ah"])).status_code == 204
        assert (await c.delete(f"/api/auth/invites/{inv.id}", headers=ctx["ah"])).status_code == 404
        assert (await c.delete("/api/auth/invites/99999999999",
                               headers=ctx["ah"])).status_code == 404
        r = await c.post("/api/auth/invites/accept", json={"token": raw, "password": PW})
        assert r.status_code == 400
        r = await c.get("/api/auth/invites", headers=ctx["ah"])
        assert r.json() == []


async def test_new_reset_supersedes_older_reset(ctx):
    member = ctx["member"]
    async with client(ctx["app"]) as c:
        t1 = (await c.post(f"/api/auth/users/{member.id}/reset", headers=ctx["ah"])).json()
        t2 = (await c.post(f"/api/auth/users/{member.id}/reset", headers=ctx["ah"])).json()
        r = await c.post("/api/auth/invites/accept",
                         json={"token": t1["token"], "password": NEW_PW})
        assert r.status_code == 400
        r = await c.post("/api/auth/invites/accept",
                         json={"token": t2["token"], "password": NEW_PW})
        assert r.status_code == 201


# ------------------------------------------------------------ hardening round 1


async def test_admin_cannot_reset_self(ctx):
    db = ctx["db"]
    async with client(ctx["app"]) as c:
        r = await c.post(f"/api/auth/users/{ctx['admin'].id}/reset", headers=ctx["ah"])
    assert r.status_code == 409 and r.json() == {"error": "cannot_modify_self"}
    assert db.scalars(select(Invite)).all() == []


async def test_reset_token_dies_after_password_change(ctx):
    member = ctx["member"]
    async with client(ctx["app"]) as c:
        tok = (await c.post(f"/api/auth/users/{member.id}/reset", headers=ctx["ah"])).json()
        r = await c.post("/api/auth/password",
                         json={"current_password": PW, "new_password": NEW_PW},
                         headers=ctx["mh"])
        assert r.status_code == 204
        r = await c.post("/api/auth/invites/accept",
                         json={"token": tok["token"], "password": "attacker passphrase"})
    assert r.status_code == 400
    assert verify_password(ctx["db"].get(User, member.id).password_hash, NEW_PW)


async def test_reset_token_dies_after_deactivate_reactivate(ctx):
    member = ctx["member"]
    async with client(ctx["app"]) as c:
        tok = (await c.post(f"/api/auth/users/{member.id}/reset", headers=ctx["ah"])).json()
        for flag in (False, True):
            r = await c.patch(f"/api/auth/users/{member.id}", json={"is_active": flag},
                              headers=ctx["ah"])
            assert r.status_code == 200
        r = await c.post("/api/auth/invites/accept",
                         json={"token": tok["token"], "password": NEW_PW})
    assert r.status_code == 400
    assert verify_password(ctx["db"].get(User, member.id).password_hash, PW)


def test_accepting_a_reset_consumes_other_outstanding_resets(db_session):
    admin = mk(db_session, "a@example.com", "admin")
    victim = mk(db_session, "v@example.com")
    t1 = create_invite(db_session, admin, victim.email, "member", 24, purpose="reset")
    t2 = create_invite(db_session, admin, victim.email, "member", 24, purpose="reset")
    accept_invite(db_session, t1, NEW_PW)
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, t2, "attacker passphrase")
    assert verify_password(victim.password_hash, NEW_PW)


# ------------------------------------------------------------ security hardening


def _rogue_setup(db):
    a = mk(db, "rogue@example.com", "admin")
    b = mk(db, "b@example.com", "admin")
    c = mk(db, "c@example.com", "admin")
    reset = create_invite(db, a, b.email, "admin", 24, purpose="reset")
    invite = create_invite(db, a, "fresh@example.com", "admin")
    return a, b, c, reset, invite


def _assert_tokens_dead(db, b, reset, invite):
    with pytest.raises(InvalidInvite):
        accept_invite(db, reset, "attacker passphrase")
    with pytest.raises(InvalidInvite):
        accept_invite(db, invite, "attacker passphrase")
    assert verify_password(b.password_hash, PW)
    assert db.scalars(select(User).where(User.email == "fresh@example.com")).first() is None


def test_deactivating_issuer_kills_their_tokens(db_session):
    a, b, c, reset, invite = _rogue_setup(db_session)
    update_user(db_session, a, is_active=False)
    _assert_tokens_dead(db_session, b, reset, invite)


def test_demoting_issuer_kills_their_tokens(db_session):
    a, b, c, reset, invite = _rogue_setup(db_session)
    update_user(db_session, a, role="member")
    _assert_tokens_dead(db_session, b, reset, invite)


def test_accept_rejects_tokens_of_inactive_or_demoted_or_missing_creator(db_session):
    a, b, c, reset, invite = _rogue_setup(db_session)
    a.is_active = False  # bypass update_user: defense in depth in accept_invite itself
    db_session.flush()
    _assert_tokens_dead(db_session, b, reset, invite)
    a.is_active, a.role = True, "member"
    db_session.flush()
    _assert_tokens_dead(db_session, b, reset, invite)
    a.role = "admin"
    db_session.flush()
    for inv in db_session.scalars(select(Invite)):
        inv.created_by = None
    db_session.flush()
    _assert_tokens_dead(db_session, b, reset, invite)


def test_invite_from_active_admin_still_works(db_session):
    a, b, c, reset, invite = _rogue_setup(db_session)
    assert accept_invite(db_session, invite, PW).email == "fresh@example.com"
    assert accept_invite(db_session, reset, NEW_PW).id == b.id
