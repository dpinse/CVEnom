"""Mandatory TOTP MFA: sign-in tickets, enrollment, verification, recovery codes.

Every failure raises the one generic `MfaFailed` (no reason attached), so the
HTTP layer can answer every failed second factor with the same bytes. Nothing
here logs a secret, ticket or code. Time is injected (`now`).

Locking order (deadlock-free): ticket row, then user row. `reset_mfa` deletes
the user's tickets before it locks the user, matching that order.

Functions flush but never commit; the caller owns the transaction.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select

from cvenom import secretbox
from cvenom.auth import totp
from cvenom.auth.users import revoke_sessions
from cvenom.models import MfaRecoveryCode, MfaTicket, User

log = logging.getLogger(__name__)

TICKET_TTL = timedelta(minutes=5)
RECOVERY_CODE_COUNT = 10
ISSUER = "CVEnom"

# Crockford base32 (no i, l, o, u): 16 symbols = 80 bits per recovery code.
_RC_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"
_RC_LEN = 16
_RC_SET = frozenset(_RC_ALPHABET)
_RC_CONFUSABLE = str.maketrans({"o": "0", "i": "1", "l": "1"})


class MfaFailed(Exception):
    """The second factor (or its ticket) was not accepted. Deliberately reasonless."""

    def __init__(self) -> None:
        super().__init__("mfa failed")


def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_enrolled(user: User) -> bool:
    return user.mfa_enabled_at is not None and user.mfa_secret_enc is not None


# ---------------------------------------------------------------- tickets


def sweep_expired_tickets(session, now: datetime) -> None:
    """Delete expired tickets; rows another transaction holds are skipped, never waited on."""
    doomed = (
        select(MfaTicket.token_hash)
        .where(MfaTicket.expires_at <= now)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    session.execute(
        delete(MfaTicket).where(MfaTicket.token_hash.in_(doomed)),
        execution_options={"synchronize_session": False},
    )


def issue_ticket(session, user: User, now: datetime) -> str:
    """A fresh 256-bit ticket for `user`, valid for TICKET_TTL. Only its hash is stored."""
    sweep_expired_tickets(session, now)
    raw = secrets.token_urlsafe(32)
    session.add(MfaTicket(token_hash=_sha256(raw), user_id=user.id, expires_at=now + TICKET_TTL))
    session.flush()
    return raw


def load_ticket(session, raw: str, now: datetime) -> tuple[MfaTicket, User]:
    """Lock and return a live ticket and its (active) user, or raise MfaFailed."""
    if not isinstance(raw, str) or not raw:
        raise MfaFailed()
    ticket = session.scalars(
        select(MfaTicket)
        .where(MfaTicket.token_hash == _sha256(raw))
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if ticket is None or ticket.expires_at <= now:
        raise MfaFailed()
    user = session.scalars(
        select(User)
        .where(User.id == ticket.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
    if user is None or not user.is_active:
        raise MfaFailed()
    return ticket, user


def _consume(session, ticket: MfaTicket) -> None:
    session.delete(ticket)
    session.flush()


# ---------------------------------------------------------------- secrets


def _decrypt(enc: str | None) -> bytes:
    if enc is None:
        raise MfaFailed()
    try:
        return secretbox.decrypt(enc)
    except secretbox.SecretsKeyMissing:
        raise
    except ValueError as exc:
        # SECRETS_KEY changed or the row is damaged; the user needs reset-mfa.
        log.warning("mfa secret undecryptable (%s)", type(exc).__name__)
        raise MfaFailed() from None


def _accept_totp(user: User, code: object, now: datetime) -> bool:
    secret = _decrypt(user.mfa_secret_enc)
    step = totp.match_step(secret, code, now.timestamp(), user.mfa_last_step)
    if step is None:
        return False
    user.mfa_last_step = step
    return True


# ---------------------------------------------------------------- recovery codes


def normalize_recovery_code(code: object) -> str | None:
    if not isinstance(code, str):
        return None
    s = "".join(code.split()).replace("-", "").lower().translate(_RC_CONFUSABLE)
    if len(s) != _RC_LEN or not set(s) <= _RC_SET:
        return None
    return s


def _recovery_hash(normalized: str) -> str:
    return _sha256("cvenom-recovery-v1:" + normalized)


def _new_recovery_code() -> str:
    s = "".join(secrets.choice(_RC_ALPHABET) for _ in range(_RC_LEN))
    return "-".join(s[i:i + 4] for i in range(0, _RC_LEN, 4))


def _replace_recovery_codes(session, user: User, now: datetime) -> list[str]:
    session.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    codes: list[str] = []
    while len(codes) < RECOVERY_CODE_COUNT:
        c = _new_recovery_code()
        if c not in codes:
            codes.append(c)
    for c in codes:
        session.add(
            MfaRecoveryCode(
                user_id=user.id,
                code_hash=_recovery_hash(normalize_recovery_code(c)),  # type: ignore[arg-type]
                created_at=now,
            )
        )
    session.flush()
    return codes


def _accept_recovery(session, user: User, code: object, now: datetime) -> bool:
    norm = normalize_recovery_code(code)
    if norm is None:
        return False
    row = session.scalars(
        select(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.code_hash == _recovery_hash(norm),
            MfaRecoveryCode.used_at.is_(None),
        )
        .with_for_update()
    ).first()
    if row is None:
        return False
    row.used_at = now
    return True


def recovery_codes_remaining(session, user: User) -> int:
    return session.scalar(
        select(func.count())
        .select_from(MfaRecoveryCode)
        .where(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None))
    ) or 0


# ---------------------------------------------------------------- flows


def verify_second_factor(session, ticket: MfaTicket, user: User, code: object,
                         now: datetime) -> None:
    """Accept a TOTP code (replay-protected) or an unused recovery code; consume the ticket."""
    if not is_enrolled(user):
        raise MfaFailed()  # unenrolled accounts can only enroll
    # Recovery first: it never touches the TOTP secret, so a user whose secret no
    # longer decrypts can still get in with a recovery code.
    if not (_accept_recovery(session, user, code, now) or _accept_totp(user, code, now)):
        raise MfaFailed()
    _consume(session, ticket)


def start_enrollment(session, ticket: MfaTicket, user: User) -> tuple[str, str]:
    """A new pending secret, held encrypted on the ticket. Returns (base32, otpauth URI)."""
    if is_enrolled(user):
        raise MfaFailed()
    secret = totp.generate_secret()
    ticket.enroll_secret_enc = secretbox.encrypt(secret)
    session.flush()
    return totp.b32(secret), totp.provisioning_uri(secret, user.email, ISSUER)


def finish_enrollment(session, ticket: MfaTicket, user: User, code: object,
                      now: datetime) -> list[str]:
    """Confirm the pending secret with a first code; returns the 10 recovery codes."""
    if is_enrolled(user) or ticket.enroll_secret_enc is None:
        raise MfaFailed()
    secret = _decrypt(ticket.enroll_secret_enc)
    step = totp.match_step(secret, code, now.timestamp(), None)
    if step is None:
        raise MfaFailed()
    user.mfa_secret_enc = ticket.enroll_secret_enc
    user.mfa_enabled_at = now
    user.mfa_last_step = step
    codes = _replace_recovery_codes(session, user, now)
    _consume(session, ticket)
    return codes


def lock_user(session, user_id: int) -> User | None:
    return session.scalars(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()


def regenerate_recovery_codes(session, user_id: int, code: object, now: datetime) -> list[str]:
    """New recovery codes (old ones die). Needs a current TOTP code, not a recovery code."""
    user = lock_user(session, user_id)
    if user is None or not is_enrolled(user) or not _accept_totp(user, code, now):
        raise MfaFailed()
    return _replace_recovery_codes(session, user, now)


def reset_mfa(session, user_id: int, now: datetime) -> bool:
    """Forget the user's MFA, recovery codes and tickets; revoke every session.

    The user must enroll again at the next sign-in. Returns False if no such user."""
    session.execute(
        delete(MfaTicket).where(MfaTicket.user_id == user_id),
        execution_options={"synchronize_session": False},
    )
    for obj in list(session.identity_map.values()):
        if isinstance(obj, MfaTicket) and obj.user_id == user_id:
            session.expunge(obj)
    user = lock_user(session, user_id)
    if user is None:
        return False
    user.mfa_secret_enc = None
    user.mfa_enabled_at = None
    user.mfa_last_step = None
    session.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id))
    revoke_sessions(session, user_id, now)
    session.flush()
    return True
