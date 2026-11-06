"""Lock order: every MFA flow takes the USER row first, then ticket row(s), the same order as
revoke_sessions (password change/reset, admin revoke, deactivation, MFA reset).

A sign-in verify racing an admin password reset must never deadlock or raise. Either the verify
wins and the reset then revokes the session it created, or the reset wins and the verify gets the
generic MFA failure (the HTTP layer's identical 401). Two real connections, committed data.
"""

import base64
import os
import threading
import time
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from cvenom.auth import mfa, totp
from cvenom.auth.passwords import hash_password
from cvenom.auth.tokens import create_session
from cvenom.auth.users import accept_invite, create_invite
from cvenom.config import get_settings
from cvenom.models import Invite, User, UserSession

NEW_PW = "a brand new passphrase"
HOLD_S = 0.7  # how long the first party keeps its locks while the other one queues up


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def world(test_engine):
    """Committed: an active admin, an enrolled victim, a pending ticket and a reset token."""
    from cvenom import secretbox

    tag = uuid.uuid4().hex[:10]
    secret = totp.generate_secret()
    now = datetime.now(UTC)
    with Session(test_engine) as s:
        admin = User(email=f"adm-{tag}@example.com", password_hash=hash_password("x" * 16),
                     role="admin", is_active=True)
        victim = User(email=f"vic-{tag}@example.com", password_hash=hash_password("y" * 16),
                      role="member", is_active=True)
        s.add_all([admin, victim])
        s.flush()
        victim.mfa_secret_enc = secretbox.encrypt(secret)
        victim.mfa_enabled_at = now
        ticket = mfa.issue_ticket(s, victim, now)
        reset = create_invite(s, admin, victim.email, "member", 24, now=now, purpose="reset")
        s.commit()
        ids = (admin.id, victim.id)
    yield {"victim": ids[1], "secret": secret, "ticket": ticket, "reset": reset}
    with Session(test_engine) as s:
        s.execute(delete(Invite).where(Invite.email == f"vic-{tag}@example.com"))
        s.execute(delete(User).where(User.id.in_(ids)))
        s.commit()


def _run(*targets):
    out: dict = {}
    threads = [threading.Thread(target=t, args=(out,)) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "deadlocked / hung"
    return out


def _verify_body(engine, w, out, *, before_check=None, after_lock=None):
    now = datetime.now(UTC)
    code = totp.totp_at(w["secret"], now.timestamp())
    try:
        with Session(engine) as s:
            if before_check:
                before_check()
            try:
                ticket, user = mfa.load_ticket(s, w["ticket"], now)
                if after_lock:
                    after_lock()
                mfa.verify_second_factor(s, ticket, user, code, now)
                row, _ = create_session(s, user, now, "ua", None)
                s.commit()
                out["verify"] = row.id
            except mfa.MfaFailed:
                s.rollback()
                out["verify"] = "failed"
    except Exception as exc:  # deadlock etc.: must never happen
        out["verify"] = exc


def _reset_body(engine, w, out, *, hold_user_lock_first=False, wait_for=None, locked=None):
    try:
        with Session(engine) as s:
            if wait_for:
                wait_for.wait(10)
            if hold_user_lock_first:
                # The reset flow locks the user before it revokes sessions and drops tickets.
                s.execute(select(User.id).where(User.id == w["victim"]).with_for_update())
                if locked:
                    locked.set()
                time.sleep(HOLD_S)
            accept_invite(s, w["reset"], NEW_PW)
            s.commit()
            out["reset"] = "ok"
    except Exception as exc:
        out["reset"] = exc


def test_verify_first_then_reset_revokes_the_new_session(test_engine, world):
    verify_locked = threading.Event()

    def verify(out):
        def hold():
            verify_locked.set()
            time.sleep(HOLD_S)  # the reset queues behind our locks meanwhile

        _verify_body(test_engine, world, out, after_lock=hold)

    def reset(out):
        _reset_body(test_engine, world, out, wait_for=verify_locked)

    out = _run(verify, reset)
    assert out["reset"] == "ok", out
    assert not isinstance(out["verify"], Exception), out
    with Session(test_engine) as s:
        if out["verify"] != "failed":
            row = s.get(UserSession, out["verify"])
            assert row.revoked_at is not None  # the reset revoked the session verify created
        assert s.scalars(select(UserSession).where(
            UserSession.user_id == world["victim"], UserSession.revoked_at.is_(None))).all() == []


def test_reset_first_then_verify_gets_the_generic_failure(test_engine, world):
    reset_locked = threading.Event()

    def reset(out):
        _reset_body(test_engine, world, out, hold_user_lock_first=True, locked=reset_locked)

    def verify(out):
        _verify_body(test_engine, world, out, before_check=lambda: reset_locked.wait(10))

    out = _run(reset, verify)
    assert out["reset"] == "ok", out
    assert out["verify"] == "failed", out  # the ticket died with the reset: identical 401
    with Session(test_engine) as s:
        assert s.scalars(select(UserSession).where(
            UserSession.user_id == world["victim"])).all() == []
