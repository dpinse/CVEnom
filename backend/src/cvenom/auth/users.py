import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cvenom.auth.passwords import (
    DUMMY_HASH,
    hash_password,
    needs_rehash,
    rehash,
    validate_password,
    verify_password,
)
from cvenom.models import Invite, User

_ROLES = ("admin", "member")
_INVALID_INVITE_MSG = "invalid or expired invite"


class AdminExists(Exception):
    pass


class InvalidInvite(Exception):
    def __init__(self) -> None:
        super().__init__(_INVALID_INVITE_MSG)


def _norm(email: str) -> str:
    return email.strip().lower()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def authenticate(session: Session, email: str, pw: str) -> User | None:
    user = session.scalars(select(User).where(User.email == _norm(email))).one_or_none()
    usable = user is not None and user.is_active
    stored = user.password_hash if usable else DUMMY_HASH
    ok = verify_password(stored, pw)  # exactly one verify on every path
    if not (usable and ok):
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = rehash(pw)
        session.flush()
    return user


def create_admin(session: Session, email: str, pw: str, *, force: bool = False) -> User:
    if not force and session.scalars(select(User.id).where(User.role == "admin").limit(1)).first():
        raise AdminExists("an admin already exists")
    user = User(email=email, password_hash=hash_password(pw), role="admin", is_active=True)
    session.add(user)
    session.flush()
    return user


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_invite(
    session: Session,
    admin: User,
    email: str,
    role: str,
    ttl_hours: int = 72,
    *,
    now: datetime | None = None,
) -> str:
    if role not in _ROLES:
        raise ValueError(f"invalid role {role!r}")
    raw = secrets.token_urlsafe(32)
    session.add(
        Invite(
            email=_norm(email),
            role=role,
            token_hash=_hash_token(raw),
            expires_at=(now or _utcnow()) + timedelta(hours=ttl_hours),
            created_by=admin.id,
        )
    )
    session.flush()
    return raw


def accept_invite(
    session: Session, token: str, pw: str, *, now: datetime | None = None
) -> User:
    now = now or _utcnow()
    invite = session.scalars(
        select(Invite).where(Invite.token_hash == _hash_token(token)).with_for_update()
    ).one_or_none()
    if invite is None or invite.used_at is not None or invite.expires_at <= now:
        raise InvalidInvite()
    validate_password(pw)  # before consuming the invite
    if session.scalars(select(User.id).where(User.email == _norm(invite.email))).first():
        raise InvalidInvite()
    user = User(email=invite.email, password_hash=hash_password(pw), role=invite.role)
    try:
        # begin_nested() flushes pending state first, so the add and the invite
        # update must happen inside the savepoint or an IntegrityError would
        # escape it and leave the outer transaction deactivated.
        with session.begin_nested():
            invite.used_at = now
            session.add(user)
            session.flush()
    except IntegrityError:
        raise InvalidInvite() from None
    return user
