"""Two-step sign-in helpers shared by the API tests (password, then TOTP)."""

from __future__ import annotations

import base64
import time
from datetime import UTC, datetime

from sqlalchemy import update

from cvenom import secretbox
from cvenom.auth import totp
from cvenom.models import User


def code_for(secret_b32: str, at: float | None = None) -> str:
    return totp.totp_at(base64.b32decode(secret_b32), time.time() if at is None else at)


def enroll_user(db, user, secret: bytes | None = None) -> str:
    """Enroll `user` directly in the DB; returns the base32 secret."""
    secret = secret or totp.generate_secret()
    user.mfa_secret_enc = secretbox.encrypt(secret)
    user.mfa_enabled_at = datetime.now(UTC)
    user.mfa_last_step = None
    db.flush()
    return totp.b32(secret)


def clear_replay(db, email: str) -> None:
    """Tests that sign the same user in twice inside one 30 s step reset replay state."""
    db.execute(update(User).where(User.email == email).values(mfa_last_step=None))
    db.flush()


async def full_login(c, email, pw, *, secret: str | None = None, headers=None, db=None):
    """Password step, then enrollment (unenrolled) or a TOTP verify (`secret` given).

    Returns the final response, or the first non-200 response along the way."""
    r = await c.post("/api/auth/login", json={"email": email, "password": pw}, headers=headers)
    if r.status_code != 200:
        return r
    body = r.json()
    ticket = body["ticket"]
    if body["enroll_required"]:
        s = await c.post("/api/auth/mfa/enroll/start", json={"ticket": ticket}, headers=headers)
        if s.status_code != 200:
            return s
        return await c.post(
            "/api/auth/mfa/enroll/finish",
            json={"ticket": ticket, "code": code_for(s.json()["secret"])},
            headers=headers,
        )
    assert secret is not None, "enrolled user: pass secret="
    if db is not None:
        clear_replay(db, email)
    return await c.post(
        "/api/auth/mfa/verify", json={"ticket": ticket, "code": code_for(secret)}, headers=headers
    )
