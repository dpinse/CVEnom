import hashlib
import io
import subprocess
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import select

from cvenom import cli
from cvenom.auth import users
from cvenom.auth.passwords import WeakPassword, hash_password, verify_password
from cvenom.auth.users import (
    AdminExists,
    InvalidInvite,
    accept_invite,
    authenticate,
    create_admin,
    create_invite,
)
from cvenom.models import Invite, User

GOOD = "correct horse battery"


def test_hash_is_argon2id_and_verifies():
    h = hash_password(GOOD)
    assert h.startswith("$argon2id$")
    assert verify_password(h, GOOD)
    assert not verify_password(h, "wrong password here")
    assert not verify_password("not-a-hash", GOOD)


@pytest.mark.parametrize("pw", ["short", "a" * 11, "a" * 257, " " * 20, "\t\n " * 8])
def test_weak_passwords_rejected(pw):
    with pytest.raises(WeakPassword):
        hash_password(pw)


def test_length_bounds_inclusive_and_in_characters():
    hash_password("a" * 12)
    hash_password("a" * 256)
    hash_password("é" * 12)  # 12 characters, 24 bytes


def test_create_admin_and_refuses_second(db_session):
    u = create_admin(db_session, "  Root@Example.com ", GOOD)
    assert u.email == "root@example.com" and u.role == "admin" and u.is_active
    assert u.password_hash.startswith("$argon2id$")
    with pytest.raises(AdminExists):
        create_admin(db_session, "other@example.com", GOOD)
    forced = create_admin(db_session, "other@example.com", GOOD, force=True)
    assert forced.role == "admin"


def test_create_admin_weak_password(db_session):
    with pytest.raises(WeakPassword):
        create_admin(db_session, "a@b.com", "short")


def test_authenticate_success_normalizes_email(db_session):
    create_admin(db_session, "a@b.com", GOOD)
    assert authenticate(db_session, " A@B.com ", GOOD).email == "a@b.com"


def _two_users(db_session):
    create_admin(db_session, "a@b.com", GOOD)
    i = create_admin(db_session, "i@b.com", GOOD, force=True)
    i.is_active = False
    db_session.flush()


def test_authenticate_failures_return_none(db_session):
    _two_users(db_session)
    assert authenticate(db_session, "a@b.com", "wrong password!!") is None
    assert authenticate(db_session, "nobody@b.com", GOOD) is None
    assert authenticate(db_session, "i@b.com", GOOD) is None


@pytest.mark.parametrize(
    "email,pw", [("nobody@b.com", GOOD), ("a@b.com", "wrong password!!"), ("i@b.com", GOOD)]
)
def test_authenticate_runs_exactly_one_verify(db_session, email, pw):
    _two_users(db_session)
    with patch.object(users, "verify_password", wraps=users.verify_password) as v:
        assert authenticate(db_session, email, pw) is None
    assert v.call_count == 1


def test_authenticate_unknown_uses_dummy_hash(db_session):
    with patch.object(users, "verify_password", return_value=False) as v:
        authenticate(db_session, "nobody@b.com", GOOD)
    assert v.call_args.args[0] == users.DUMMY_HASH
    assert users.DUMMY_HASH.startswith("$argon2id$")


def test_authenticate_corrupt_stored_hash_returns_none(db_session):
    u = create_admin(db_session, "a@b.com", GOOD)
    u.password_hash = "garbage"
    db_session.flush()
    assert authenticate(db_session, "a@b.com", GOOD) is None


def test_authenticate_rehashes_when_needed(db_session):
    u = create_admin(db_session, "a@b.com", GOOD)
    old = u.password_hash
    with patch.object(users, "needs_rehash", return_value=True):
        assert authenticate(db_session, "a@b.com", GOOD) is not None
    db_session.refresh(u)
    assert u.password_hash != old and verify_password(u.password_hash, GOOD)


NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_invite_single_use_and_hashed(db_session):
    admin = create_admin(db_session, "a@b.com", GOOD)
    token = create_invite(db_session, admin, " New@B.com ", "member", now=NOW)
    inv = db_session.scalars(select(Invite)).one()
    assert inv.email == "new@b.com" and inv.created_by == admin.id
    assert inv.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert token not in (inv.token_hash, inv.email)
    assert inv.expires_at == NOW + timedelta(hours=72)
    user = accept_invite(db_session, token, GOOD, now=NOW + timedelta(hours=1))
    assert user.email == "new@b.com" and user.role == "member"
    assert inv.used_at is not None
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, token, GOOD, now=NOW + timedelta(hours=1))


def test_invite_expired_unknown_used_same_message(db_session):
    admin = create_admin(db_session, "a@b.com", GOOD)
    t1 = create_invite(db_session, admin, "x@b.com", "member", ttl_hours=1, now=NOW)
    msgs = set()
    for tok, now in [(t1, NOW + timedelta(hours=2)), ("bogus", NOW)]:
        with pytest.raises(InvalidInvite) as e:
            accept_invite(db_session, tok, GOOD, now=now)
        msgs.add(str(e.value))
    t2 = create_invite(db_session, admin, "y@b.com", "member", now=NOW)
    accept_invite(db_session, t2, GOOD, now=NOW)
    with pytest.raises(InvalidInvite) as e:
        accept_invite(db_session, t2, GOOD, now=NOW)
    msgs.add(str(e.value))
    assert len(msgs) == 1


def test_invite_for_existing_email_is_invalid_invite(db_session):
    admin = create_admin(db_session, "a@b.com", GOOD)
    t = create_invite(db_session, admin, "A@B.com", "member", now=NOW)
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, t, GOOD, now=NOW)
    assert db_session.scalars(select(User)).all()  # session still usable


def test_invite_weak_password_does_not_consume(db_session):
    admin = create_admin(db_session, "a@b.com", GOOD)
    t = create_invite(db_session, admin, "n@b.com", "member", now=NOW)
    with pytest.raises(WeakPassword):
        accept_invite(db_session, t, "short", now=NOW)
    assert accept_invite(db_session, t, GOOD, now=NOW).email == "n@b.com"


def test_invite_bad_role(db_session):
    admin = create_admin(db_session, "a@b.com", GOOD)
    with pytest.raises(ValueError):
        create_invite(db_session, admin, "n@b.com", "root", now=NOW)


# ---- CLI ----


def _factory(session):
    @contextmanager
    def scope():
        yield session

    return scope


def test_cli_creates_admin_from_env(db_session, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_PASSWORD", GOOD)
    rc = cli.main(["create-admin", "--email", "Boss@X.com"], session_factory=_factory(db_session))
    out = capsys.readouterr().out
    assert rc == 0 and out.strip() == "created admin boss@x.com"
    assert GOOD not in out and "argon2" not in out
    assert db_session.scalars(select(User)).one().role == "admin"


def test_cli_reads_password_from_stdin(db_session, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(GOOD + "\n"))
    rc = cli.main(["create-admin", "--email", "b@x.com"], session_factory=_factory(db_session))
    assert rc == 0
    assert verify_password(db_session.scalars(select(User)).one().password_hash, GOOD)


def test_cli_uses_getpass_on_tty(db_session, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)

    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", Tty())
    with patch.object(cli.getpass, "getpass", return_value=GOOD) as g:
        rc = cli.main(["create-admin", "--email", "b@x.com"], session_factory=_factory(db_session))
    assert rc == 0 and g.called


def test_cli_weak_password_exit_1(db_session, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_PASSWORD", "short")
    rc = cli.main(["create-admin", "--email", "b@x.com"], session_factory=_factory(db_session))
    cap = capsys.readouterr()
    assert rc == 1 and cap.out == "" and cap.err


def test_cli_admin_exists_exit_1(db_session, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", GOOD)
    f = _factory(db_session)
    assert cli.main(["create-admin", "--email", "a@x.com"], session_factory=f) == 0
    assert cli.main(["create-admin", "--email", "b@x.com"], session_factory=f) == 1


def test_cli_rejects_password_argument():
    r = subprocess.run(
        [sys.executable, "-m", "cvenom.cli", "create-admin", "--email", "a@b.com", "--password", "x" * 20],
        capture_output=True,
        text=True,
    )
    assert r.returncode != 0
    assert "unrecognized arguments" in r.stderr


def test_authenticate_rehash_skips_password_policy(db_session):
    """A legacy account whose password violates today's policy can still log in."""
    short = "short"
    u = create_admin(db_session, "a@b.com", GOOD)
    u.password_hash = passwords_rehash(short)
    db_session.flush()
    with patch.object(users, "needs_rehash", return_value=True):
        assert authenticate(db_session, "a@b.com", short) is not None
    assert verify_password(u.password_hash, short)


def passwords_rehash(pw):
    from cvenom.auth.passwords import rehash

    return rehash(pw)


def test_dummy_verify_runs_without_error():
    from cvenom.auth.passwords import dummy_verify

    assert dummy_verify("anything") is None


def test_accept_invite_integrity_error_maps_to_invalid_invite(db_session, monkeypatch):
    admin = create_admin(db_session, "a@b.com", GOOD)
    raw = create_invite(db_session, admin, "dup@x.com", "member")
    # Make the pre-check miss, then collide with an existing user at flush time.
    db_session.add(User(email="dup@x.com", password_hash="x", role="member"))
    db_session.flush()
    real_scalars = db_session.scalars
    calls = {"n": 0}

    class Empty:
        def first(self):
            return None

    def fake(stmt, *a, **k):
        if "app_user" in str(stmt) and "invite" not in str(stmt):
            calls["n"] += 1
            return Empty()
        return real_scalars(stmt, *a, **k)

    monkeypatch.setattr(db_session, "scalars", fake)
    with pytest.raises(InvalidInvite):
        accept_invite(db_session, raw, GOOD)
    assert calls["n"] == 1
    monkeypatch.undo()
    inv = db_session.scalars(select(Invite)).one()
    assert inv.used_at is None  # savepoint rolled the consumption back


def test_cli_email_exists_as_non_admin_clean_exit(db_session, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_PASSWORD", GOOD)
    db_session.add(User(email="m@x.com", password_hash="SECRETHASH", role="member"))
    db_session.flush()
    rc = cli.main(["create-admin", "--email", "m@x.com"], session_factory=_factory(db_session))
    cap = capsys.readouterr()
    assert rc == 1 and cap.out == ""
    assert "SECRETHASH" not in cap.err and "INSERT" not in cap.err and "argon2" not in cap.err


# ------------------------------------- M-k: bounded concurrent argon2 verifies


@pytest.mark.parametrize("call", ["verify", "dummy"])
def test_fifth_concurrent_verify_waits_for_a_permit(call):
    import threading

    from cvenom.auth import passwords

    assert passwords.VERIFY_CONCURRENCY == 4
    slots = passwords._VERIFY_SLOTS
    held = 0
    for _ in range(4):
        assert slots.acquire(timeout=1)
        held += 1
    done = threading.Event()

    def worker():
        if call == "verify":
            passwords.verify_password(passwords.DUMMY_HASH, "x")
        else:
            passwords.dummy_verify("x")
        done.set()

    t = threading.Thread(target=worker, daemon=True)
    try:
        t.start()
        assert not done.wait(0.3)  # all permits held: the fifth verify blocks
        slots.release()
        held -= 1
        assert done.wait(5)
    finally:
        for _ in range(held):
            slots.release()
        t.join(5)
