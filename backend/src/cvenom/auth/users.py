import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
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
from cvenom.models import Invite, MfaTicket, User, UserSession

_ROLES = ("admin", "member")
_PURPOSES = ("invite", "reset")
_INVALID_INVITE_MSG = "invalid or expired invite"


class AdminExists(Exception):
    pass


class LastAdmin(Exception):
    """The change would leave the system without an active admin."""


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
    purpose: str = "invite",
) -> str:
    if role not in _ROLES:
        raise ValueError(f"invalid role {role!r}")
    if purpose not in _PURPOSES:
        raise ValueError(f"invalid purpose {purpose!r}")
    raw = secrets.token_urlsafe(32)
    session.add(
        Invite(
            email=_norm(email),
            role=role,
            token_hash=_hash_token(raw),
            expires_at=(now or _utcnow()) + timedelta(hours=ttl_hours),
            created_by=admin.id,
            purpose=purpose,
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
    if invite.purpose not in _PURPOSES:
        raise InvalidInvite()
    # Tokens are only as trustworthy as their issuer: the creator must still be an
    # active admin (also rejects creator-less rows; no legitimate path makes them).
    creator = session.get(User, invite.created_by) if invite.created_by is not None else None
    if creator is None or not creator.is_active or creator.role != "admin":
        raise InvalidInvite()
    validate_password(pw)  # before consuming the invite
    if invite.purpose == "reset":
        return _accept_reset(session, invite, pw, now)
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


def _accept_reset(session: Session, invite: Invite, pw: str, now: datetime) -> User:
    """Set an EXISTING active user's password; never creates an account."""
    user = session.scalars(
        select(User).where(User.email == _norm(invite.email)).with_for_update()
    ).one_or_none()
    if user is None or not user.is_active:
        raise InvalidInvite()
    user.password_hash = hash_password(pw)
    revoke_sessions(session, user.id, now)  # every device must sign in again
    invite.used_at = now
    consume_resets(session, user.email, now)  # any other outstanding resets die too
    session.flush()
    return user


def consume_resets(session: Session, email: str, now: datetime) -> None:
    """Invalidate every unused reset token for this address."""
    session.execute(
        update(Invite)
        .where(Invite.email == _norm(email), Invite.purpose == "reset",
               Invite.used_at.is_(None))
        .values(used_at=now)
    )


def create_reset(session: Session, admin: User, user: User, ttl_hours: int = 24,
                 *, now: datetime | None = None) -> tuple[str, datetime]:
    """Single-use password-reset token for `user`; older unused resets for the
    same address are invalidated. Returns (raw token, expires_at)."""
    now = now or _utcnow()
    consume_resets(session, user.email, now)
    raw = create_invite(session, admin, user.email, user.role, ttl_hours, now=now,
                        purpose="reset")
    return raw, now + timedelta(hours=ttl_hours)


def drop_mfa_tickets(session: Session, user_id: int) -> None:
    """Delete the user's pending MFA sign-in tickets (and their pending enrollment secrets)."""
    session.execute(
        delete(MfaTicket).where(MfaTicket.user_id == user_id),
        execution_options={"synchronize_session": False},
    )
    for obj in list(session.identity_map.values()):
        if isinstance(obj, MfaTicket) and obj.user_id == user_id:
            session.expunge(obj)


def revoke_sessions(session: Session, user_id: int, now: datetime, *,
                    except_sid=None) -> int:
    """Revoke the user's live sessions (all, or all but `except_sid`).

    Pending MFA tickets die too: every caller is a credential or access change
    (password change/reset, admin revoke, deactivation, MFA reset), and a ticket
    minted under the old state must not be able to finish a sign-in afterwards."""
    drop_mfa_tickets(session, user_id)
    stmt = update(UserSession).where(
        UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
    )
    if except_sid is not None:
        stmt = stmt.where(UserSession.id != except_sid)
    count = session.execute(
        stmt.values(revoked_at=now).execution_options(synchronize_session=False)
    ).rowcount
    # The bulk UPDATE bypasses the identity map: expire any cached rows of this user
    # so a later session.get() in the same request cannot see a stale live session.
    for obj in list(session.identity_map.values()):
        if isinstance(obj, UserSession) and obj.user_id == user_id:
            session.expire(obj)
    return count


def update_user(session: Session, target: User, *, role: str | None = None,
                is_active: bool | None = None, now: datetime | None = None) -> User:
    """Change role / active flag. Deactivation revokes all sessions in the same
    transaction. Raises LastAdmin if no active admin would remain."""
    if role is not None and role not in _ROLES:
        raise ValueError(f"invalid role {role!r}")
    now = now or _utcnow()
    if role is None and is_active is None:
        return target
    # Lock every active admin row (fixed id order: no deadlocks) BEFORE counting, so
    # two concurrent demotions serialize and the second sees the first's result.
    admins = session.scalars(
        select(User).where(User.role == "admin", User.is_active.is_(True))
        .order_by(User.id).with_for_update()
        .execution_options(populate_existing=True)
    ).all()
    new_role = target.role if role is None else role
    new_active = target.is_active if is_active is None else is_active
    was_admin = target.role == "admin" and target.is_active
    if was_admin and not (new_role == "admin" and new_active) and len(admins) <= 1:
        raise LastAdmin()
    target.role = new_role
    target.is_active = new_active
    if not new_active:
        revoke_sessions(session, target.id, now)
        consume_resets(session, target.email, now)
    if not new_active or new_role != "admin":
        # Tokens this user issued must not outlive their authority.
        session.execute(
            update(Invite)
            .where(Invite.created_by == target.id, Invite.used_at.is_(None))
            .values(used_at=now)
        )
    session.flush()
    return target
