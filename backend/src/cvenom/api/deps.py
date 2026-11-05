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


def _unauthorized(error: str = "invalid_token") -> HTTPException:
    return HTTPException(
        status_code=401, detail={"error": error}, headers={"WWW-Authenticate": "Bearer"}
    )


def current_user(request: Request, session: Session = Depends(get_session)) -> User | None:
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized()
    now = datetime.now(UTC)
    try:
        claims = decode_access(session, token, now=now)
    except InvalidToken:
        raise _unauthorized() from None
    if not session_is_active(session, claims.sid, now):
        raise _unauthorized()
    user = session.get(User, claims.sub)
    if user is None or not user.is_active:
        raise _unauthorized()
    request.state.claims = claims
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
