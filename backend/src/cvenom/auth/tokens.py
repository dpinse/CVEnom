"""Rotating Ed25519 JWT key ring, access tokens, and rotating refresh tokens.

Time is always injected (`now`) so behaviour is deterministic and testable.
Functions flush but never commit, with one deliberate exception: see
`rotate_refresh` (reuse detection).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from collections import OrderedDict
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from cvenom import secretbox
from cvenom.config import get_settings
from cvenom.models import SigningKey, User, UserSession, UserSessionUsedRefresh

log = logging.getLogger(__name__)

ALGORITHM = "EdDSA"
# Fixed int64 key for the transaction-scoped advisory lock guarding key creation.
_KEY_RING_LOCK_ID = 0x43564E4B455952  # "CVNKEYR"
_IAT_LEEWAY = timedelta(seconds=60)
# A client racing itself (two concurrent refreshes with the same token) must not
# lose its session: the immediate predecessor is tolerated inside this window.
REUSE_GRACE = timedelta(seconds=10)
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "sid", "kid", "iss", "aud"]


# Process-wide cache of signing-key rows (kid, public key, retired_at). The grace
# window is applied at use time against the caller's `now`, never at fetch time.
KEY_CACHE_TTL_S = 60.0
KEY_FORCE_REFRESH_MIN_S = 10.0  # per unknown kid
KEY_FORCE_REFRESH_GLOBAL_S = 1.0  # across all kids
_KID_TRACK_MAX = 256
_key_cache_lock = threading.Lock()
_key_cache: tuple[float, list[tuple[str, Ed25519PublicKey, datetime | None]]] | None = None
_last_forced_refresh: float | None = None  # global
_kid_refresh: OrderedDict[str, float] = OrderedDict()
_KEY_CREATED = "cvenom_key_created"


def reset_key_cache() -> None:
    global _key_cache, _last_forced_refresh
    with _key_cache_lock:
        _key_cache = None
        _last_forced_refresh = None
        _kid_refresh.clear()


def _invalidate_key_cache() -> None:
    global _key_cache
    with _key_cache_lock:
        _key_cache = None


class InvalidToken(Exception):
    """Token is invalid. Messages are deliberately generic and never contain the token."""


class TokenReuse(InvalidToken):
    """A rotated-out refresh token was presented again (possible theft)."""


@dataclass(frozen=True)
class AccessClaims:
    sub: int
    sid: uuid.UUID
    role: str
    kid: str
    iat: int
    exp: int


def _require_aware(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")


class KeyRing:
    @staticmethod
    def _generate(now: datetime) -> SigningKey:
        priv = Ed25519PrivateKey.generate()
        der = priv.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return SigningKey(
            kid=secrets.token_urlsafe(16),
            private_enc=secretbox.encrypt(der),
            public_pem=pub_pem.decode("ascii"),
            created_at=now,
            retired_at=None,
        )

    @staticmethod
    def _active(session: Session, refresh: bool = False) -> SigningKey | None:
        stmt = (
            select(SigningKey)
            .where(SigningKey.retired_at.is_(None))
            .order_by(SigningKey.created_at.desc())
            .limit(1)
        )
        if refresh:
            stmt = stmt.execution_options(populate_existing=True)
        return session.scalars(stmt).first()

    @staticmethod
    def current(
        session: Session, now: datetime, *, discard_kid: str | None = None
    ) -> SigningKey:
        """Return the active signing key, creating/rotating it when needed.

        `discard_kid` names an active key that must not be returned (its private
        half is undecryptable); it is retired and replaced unless another worker
        already did so.

        Flushes but does not commit; the caller owns the transaction.
        """
        _require_aware(now)
        rotate_after = timedelta(days=get_settings().jwt_rotation_days)

        def usable(k: SigningKey | None) -> bool:
            return (
                k is not None
                and k.created_at > now - rotate_after
                and k.kid != discard_kid
            )

        key = KeyRing._active(session)
        if usable(key):
            return key  # type: ignore[return-value]

        # Serialize creation across workers; released at transaction end.
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _KEY_RING_LOCK_ID})
        # Re-check: another worker may have created a key while we waited.
        key = KeyRing._active(session, refresh=True)
        if usable(key):
            return key  # type: ignore[return-value]

        for old in session.scalars(select(SigningKey).where(SigningKey.retired_at.is_(None))):
            old.retired_at = now
        new = KeyRing._generate(now)
        session.add(new)
        session.flush()
        session.info[_KEY_CREATED] = True
        _invalidate_key_cache()
        return new

    @staticmethod
    def signing_key(session: Session, now: datetime) -> tuple[SigningKey, Ed25519PrivateKey]:
        """The active key with its decrypted private half.

        If SECRETS_KEY changed, the stored private key no longer decrypts; the
        key is retired and a fresh one created (under the advisory lock) instead
        of failing every login until it ages out. A missing or malformed
        SECRETS_KEY still raises: no new key could be encrypted either.
        """
        key = KeyRing.current(session, now)
        try:
            return key, _load_private(key)
        except secretbox.SecretsKeyMissing:
            raise
        except ValueError as exc:
            secretbox.check_key()  # raises if SECRETS_KEY itself is unusable
            log.warning("signing key undecryptable; rotating (%s)", type(exc).__name__)
        key = KeyRing.current(session, now, discard_kid=key.kid)
        return key, _load_private(key)

    @staticmethod
    def _load_keys(
        session: Session,
    ) -> list[tuple[str, Ed25519PublicKey, datetime | None]]:
        rows = session.scalars(select(SigningKey)).all()
        out: list[tuple[str, Ed25519PublicKey, datetime | None]] = []
        for row in rows:
            pub = serialization.load_pem_public_key(row.public_pem.encode("ascii"))
            if isinstance(pub, Ed25519PublicKey):
                out.append((row.kid, pub, row.retired_at))
        return out

    @staticmethod
    def verification_keys(
        session: Session, now: datetime, *, force: bool = False
    ) -> dict[str, Ed25519PublicKey]:
        """Active key plus keys retired within access_ttl + 1h (grace window).

        Backed by a process-wide cache (TTL 60 s); `force` bypasses it.
        """
        global _key_cache
        _require_aware(now)
        grace = timedelta(minutes=get_settings().access_ttl_minutes) + timedelta(hours=1)
        mono = time.monotonic()
        cached = _key_cache
        if force or cached is None or mono - cached[0] >= KEY_CACHE_TTL_S:
            entries = KeyRing._load_keys(session)
            with _key_cache_lock:
                _key_cache = (mono, entries)
        else:
            entries = cached[1]
        cutoff = now - grace
        return {
            kid: pub for kid, pub, retired in entries if retired is None or retired > cutoff
        }


def _load_private(key: SigningKey) -> Ed25519PrivateKey:
    priv = serialization.load_der_private_key(secretbox.decrypt(key.private_enc), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("signing key is not Ed25519")
    return priv


def issue_access(session: Session, user: User, sid: uuid.UUID, now: datetime) -> str:
    _require_aware(now)
    s = get_settings()
    key, priv = KeyRing.signing_key(session, now)
    iat = int(now.timestamp())
    claims = {
        "sub": str(user.id),
        "sid": str(sid),
        "role": user.role,
        "iat": iat,
        "exp": iat + s.access_ttl_minutes * 60,
        "kid": key.kid,
        "iss": s.jwt_issuer,
        "aud": s.jwt_audience,
    }
    return jwt.encode(claims, priv, algorithm=ALGORITHM, headers={"kid": key.kid})  # type: ignore[arg-type]


def _may_force_refresh(kid: str) -> bool:
    """One forced refresh per unknown kid per 10 s (bounded LRU), and at most one
    forced refresh per second overall, so bogus kids cannot starve a real one."""
    global _last_forced_refresh
    mono = time.monotonic()
    with _key_cache_lock:
        if _last_forced_refresh is not None and mono - _last_forced_refresh < KEY_FORCE_REFRESH_GLOBAL_S:
            return False
        last = _kid_refresh.get(kid)
        if last is not None and mono - last < KEY_FORCE_REFRESH_MIN_S:
            return False
        _last_forced_refresh = mono
        _kid_refresh[kid] = mono
        _kid_refresh.move_to_end(kid)
        while len(_kid_refresh) > _KID_TRACK_MAX:
            _kid_refresh.popitem(last=False)
        return True


@event.listens_for(Session, "after_commit")
def _after_commit(session: Session) -> None:
    if session.info.pop(_KEY_CREATED, False):
        _invalidate_key_cache()


@event.listens_for(Session, "after_rollback")
def _after_rollback(session: Session) -> None:
    session.info.pop(_KEY_CREATED, None)


def decode_access(session: Session, token: str, now: datetime) -> AccessClaims:
    _require_aware(now)
    s = get_settings()
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise InvalidToken("invalid token") from None
    kid = header.get("kid")
    if header.get("alg") != ALGORITHM or not isinstance(kid, str):
        raise InvalidToken("invalid token")
    pub = KeyRing.verification_keys(session, now).get(kid)
    if pub is None and _may_force_refresh(kid):
        # Unknown kid: a key created by another worker? One refresh, rate-limited.
        pub = KeyRing.verification_keys(session, now, force=True).get(kid)
    if pub is None:
        raise InvalidToken("invalid token")
    try:
        payload = jwt.decode(
            token,
            pub,
            algorithms=[ALGORITHM],
            audience=s.jwt_audience,
            issuer=s.jwt_issuer,
            options={"require": _REQUIRED_CLAIMS, "verify_exp": False, "verify_iat": False},
        )
        exp, iat = payload["exp"], payload["iat"]
        if not isinstance(exp, int) or not isinstance(iat, int) or isinstance(exp, bool) or isinstance(iat, bool):
            raise InvalidToken("invalid token")
        now_ts = now.timestamp()
        if exp <= now_ts or iat > now_ts + _IAT_LEEWAY.total_seconds():
            raise InvalidToken("invalid token")
        if payload["kid"] != kid:
            raise InvalidToken("invalid token")
        return AccessClaims(
            sub=int(payload["sub"]),
            sid=uuid.UUID(str(payload["sid"])),
            role=str(payload["role"]),
            kid=kid,
            iat=iat,
            exp=exp,
        )
    except InvalidToken:
        raise
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        raise InvalidToken("invalid token") from None


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_refresh() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, _hash(raw)


def create_session(
    session: Session, user: User, now: datetime, ua: str | None, ip: str | None
) -> tuple[UserSession, str]:
    _require_aware(now)
    raw, h = new_refresh()
    row = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        refresh_hash=h,
        user_agent=(ua or "")[:512] or None,
        ip=(ip or "")[:64] or None,
        created_at=now,
        last_used_at=now,
        expires_at=now + timedelta(days=get_settings().refresh_ttl_days),
    )
    session.add(row)
    session.flush()
    return row, raw


def rotate_refresh(
    session: Session, raw: str, now: datetime, ua: str | None, ip: str | None
) -> tuple[UserSession, str]:
    """Exchange a refresh token for a new one (same session id).

    Reuse detection: every hash a session has rotated away from is recorded in
    `user_session_used_refresh`. Presenting any of them again means someone holds
    a stale copy, so the session is revoked and this function COMMITS before
    raising `TokenReuse`, so the revocation survives the caller's rollback on the
    error path. This is the only place in this module that commits.

    Exception: the immediate predecessor presented within `REUSE_GRACE` of the
    last rotation is treated as a client racing itself; it gets a plain
    `InvalidToken` and the session is left untouched.
    """
    _require_aware(now)
    h = _hash(raw)
    row = session.scalars(
        select(UserSession).where(UserSession.refresh_hash == h).with_for_update()
    ).first()
    if row is None:
        used = session.get(UserSessionUsedRefresh, h)
        reused = (
            session.scalars(
                select(UserSession).where(UserSession.id == used.session_id).with_for_update()
            ).first()
            if used is not None
            else None
        )
        if reused is not None:
            if reused.prev_refresh_hash == h and now - reused.last_used_at < REUSE_GRACE:
                raise InvalidToken("invalid refresh token")
            if reused.revoked_at is None:
                reused.revoked_at = now
            session.commit()
            raise TokenReuse("refresh token reuse detected")
        raise InvalidToken("invalid refresh token")

    user = session.get(User, row.user_id)
    if (
        row.revoked_at is not None
        or row.expires_at <= now
        or user is None
        or not user.is_active
    ):
        raise InvalidToken("invalid refresh token")

    new_raw, new_hash = new_refresh()
    session.add(UserSessionUsedRefresh(hash=row.refresh_hash, session_id=row.id, used_at=now))
    row.prev_refresh_hash = row.refresh_hash
    row.refresh_hash = new_hash
    row.last_used_at = now
    row.user_agent = (ua or "")[:512] or None
    row.ip = (ip or "")[:64] or None
    session.flush()
    return row, new_raw


def session_is_active(session: Session, sid: uuid.UUID, now: datetime) -> bool:
    _require_aware(now)
    row = session.get(UserSession, sid)
    return row is not None and row.revoked_at is None and row.expires_at > now
