"""FastAPI dependencies: DB session and authentication/authorisation."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from cvenom.auth.tokens import InvalidToken, decode_access, session_is_active
from cvenom.models import User

from .middleware import client_ip  # noqa: F401  (re-exported)


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as s:
        yield s


# scope="function": the session context exits (and commits) BEFORE the response is
# sent, so a failed commit becomes a 500 instead of a success the DB never saw.
# Every dependant must use this same object so there is one session per request.
SessionDep = Depends(get_session, scope="function")


def _unauthorized(error: str = "invalid_token") -> HTTPException:
    return HTTPException(
        status_code=401, detail={"error": error}, headers={"WWW-Authenticate": "Bearer"}
    )


def resolve_access(session: Session, token: str, now: datetime):
    """Shared by HTTP and WebSocket auth: decode the JWT, require a live
    session and an active user. Returns (claims, user) or None."""
    try:
        claims = decode_access(session, token, now=now)
    except InvalidToken:
        return None
    if not session_is_active(session, claims.sid, now):
        return None
    user = session.get(User, claims.sub)
    if user is None or not user.is_active:
        return None
    return claims, user


def try_current_user(
    request: Request, session: Session = SessionDep
) -> tuple[User | None, bool]:
    """Non-raising identity resolution: (user, auth_failed).

    No Authorization header -> (None, False). Any invalid credential ->
    (None, True) so callers can rate-limit before answering 401."""
    header = request.headers.get("authorization")
    if header is None:
        return None, False
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None, True
    now = datetime.now(UTC)
    resolved = resolve_access(session, token, now)
    if resolved is None:
        return None, True
    claims, user = resolved
    request.state.claims = claims
    return user, False


def current_user(
    request: Request, resolved: tuple[User | None, bool] = Depends(try_current_user)
) -> User | None:
    user, failed = resolved
    if failed:
        raise _unauthorized()
    return user


def require_user(user: User | None = Depends(current_user)) -> User:
    if user is None:
        raise _unauthorized("unauthorized")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail={"error": "forbidden"})
    return user


def public_or_user(request: Request, user: User | None = Depends(current_user)) -> User | None:
    if user is None and not request.app.state.settings.public_read:
        raise _unauthorized("unauthorized")
    return user
