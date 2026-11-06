"""Review fix 2: real concurrency, with separate connections and committed data.

Two threads, each with its own Session on its own pooled connection, race to spend the
same TOTP step (on two different tickets) or the same recovery code. Exactly one may win.

How the race is forced: each thread first loads the user into its session (as an earlier
read in the same request would), resolves its ticket, then meets the other thread at a
barrier before checking the code.
- With the row locks, the second thread blocks inside `load_ticket` (user row FOR UPDATE).
  The barrier times out for the first thread, which then commits. The second thread
  resumes, re-reads the row (populate_existing) and is rejected.
- Without `with_for_update`, or without `populate_existing` (the stale preloaded user
  would be returned), both threads pass the barrier holding `mfa_last_step = None`, and
  both succeed. That makes this test fail.
"""

import base64
import os
import threading
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session

from cvenom.auth import mfa, totp
from cvenom.auth.passwords import hash_password
from cvenom.config import get_settings
from cvenom.models import User

BARRIER_TIMEOUT_S = 2.0


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def committed_user(test_engine):
    """An enrolled user COMMITTED to the test database (not the per-test rollback session)."""
    from cvenom import secretbox

    secret = totp.generate_secret()
    email = f"race-{uuid.uuid4().hex[:12]}@example.com"
    with Session(test_engine) as s:
        u = User(email=email, password_hash=hash_password("correct horse battery"),
                 role="member", is_active=True)
        s.add(u)
        s.flush()
        u.mfa_secret_enc = secretbox.encrypt(secret)
        u.mfa_enabled_at = datetime.now(UTC)
        codes = mfa._replace_recovery_codes(s, u, datetime.now(UTC))
        s.commit()
        uid = u.id
    yield uid, secret, codes
    with Session(test_engine) as s:  # cascades to tickets and recovery codes
        s.execute(delete(User).where(User.id == uid))
        s.commit()


def _tickets(engine, uid, n):
    now = datetime.now(UTC)
    with Session(engine) as s:
        user = s.get(User, uid)
        raws = [mfa.issue_ticket(s, user, now) for _ in range(n)]
        s.commit()
    return raws


def _race(engine, uid, attempts):
    """Run `attempts` [(ticket, code), ...] concurrently; returns [True/False/Exception]."""
    barrier = threading.Barrier(len(attempts))
    results: list = [None] * len(attempts)
    now = datetime.now(UTC)

    def worker(i, raw, code):
        try:
            with Session(engine) as s:
                # An earlier read in the same request (as require_user does), kept referenced:
                # the identity map is weak, so an unreferenced copy would be collected and the
                # later SELECT would load fresh anyway, hiding a missing populate_existing.
                preloaded = s.get(User, uid)
                assert preloaded is not None
                try:
                    ticket, user = mfa.load_ticket(s, raw, now)
                    try:
                        barrier.wait(timeout=BARRIER_TIMEOUT_S)
                    except threading.BrokenBarrierError:
                        pass  # the other thread is blocked on our row lock: expected with locks
                    mfa.verify_second_factor(s, ticket, user, code, now)
                    s.commit()
                    results[i] = True
                except mfa.MfaFailed:
                    s.rollback()
                    results[i] = False
        except Exception as exc:  # surfaced by the assertion below
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i, raw, code))
               for i, (raw, code) in enumerate(attempts)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "a worker hung"
    return results


def test_same_totp_step_on_two_tickets_concurrently_exactly_one_wins(test_engine, committed_user):
    uid, secret, _codes = committed_user
    code = totp.totp_at(secret, datetime.now(UTC).timestamp())
    t1, t2 = _tickets(test_engine, uid, 2)
    results = _race(test_engine, uid, [(t1, code), (t2, code)])
    assert sorted(results, key=str) == [False, True], results
    with Session(test_engine) as s:
        assert s.get(User, uid).mfa_last_step is not None


def test_same_recovery_code_concurrently_exactly_one_wins(test_engine, committed_user):
    uid, _secret, codes = committed_user
    t1, t2 = _tickets(test_engine, uid, 2)
    results = _race(test_engine, uid, [(t1, codes[0]), (t2, codes[0])])
    assert sorted(results, key=str) == [False, True], results
    with Session(test_engine) as s:
        assert mfa.recovery_codes_remaining(s, s.get(User, uid)) == mfa.RECOVERY_CODE_COUNT - 1
