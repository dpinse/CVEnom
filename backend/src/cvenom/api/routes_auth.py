"""Auth HTTP API: login, cookie refresh, logout, me, sessions, invites."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from cvenom.auth.passwords import MAX_LENGTH, WeakPassword, dummy_verify
from cvenom.auth.tokens import (
    InvalidToken,
    create_session,
    issue_access,
    rotate_refresh,
)
from cvenom.auth.users import InvalidInvite, accept_invite, authenticate, create_invite
from cvenom.models import User, UserSession

from .deps import SessionDep, client_ip, require_admin, require_user
from .ratelimit import enforce_login_limits, rate_limit

router = APIRouter(prefix="/api/auth")

COOKIE_NAME = "cvenom_refresh"
COOKIE_PATH = "/api/auth"
INVITE_TTL_HOURS = 72
_MAX_REFRESH_LEN = 256


def _now() -> datetime:
    return datetime.now(UTC)


def _cookie(value: str, max_age: int) -> str:
    # Built by hand so the attribute set/casing is exact and auditable.
    return (
        f"{COOKIE_NAME}={value}; HttpOnly; Secure; SameSite=Strict; "
        f"Path={COOKIE_PATH}; Max-Age={max_age}"
    )


def _set_refresh(response: Response, request: Request, raw: str) -> None:
    days = request.app.state.settings.refresh_ttl_days
    response.headers.append("set-cookie", _cookie(raw, days * 86400))


def _clear_refresh(response: Response) -> None:
    response.headers.append("set-cookie", _cookie("", 0))


def _error(status: int, error: str) -> JSONResponse:
    return JSONResponse({"error": error}, status_code=status)


def _user_json(u: User) -> dict:
    return {"id": u.id, "email": u.email, "role": u.role}


# ---------------------------------------------------------------- login


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


def _login_sync(session: Session, request: Request, body: LoginBody) -> JSONResponse:
    if len(body.password) > MAX_LENGTH:
        dummy_verify(body.password)
        return _error(401, "invalid_credentials")
    user = authenticate(session, body.email, body.password)
    if user is None:
        return _error(401, "invalid_credentials")
    now = _now()
    row, raw = create_session(
        session,
        user,
        now,
        request.headers.get("user-agent", ""),
        client_ip(request),
    )
    access = issue_access(session, user, row.id, now)
    resp = JSONResponse(
        {
            "access_token": access,
            "token_type": "bearer",
            "expires_in": request.app.state.settings.access_ttl_minutes * 60,
        }
    )
    _set_refresh(resp, request, raw)
    return resp


@router.post("/login")
async def login(
    request: Request, body: LoginBody, session: Session = SessionDep
) -> JSONResponse:
    await enforce_login_limits(request, body.email)  # before any DB work
    return await run_in_threadpool(_login_sync, session, request, body)


# ---------------------------------------------------------------- refresh


def _refresh_sync(session: Session, request: Request, raw: str) -> JSONResponse:
    now = _now()
    try:
        # First DB write of the handler (reuse detection commits inside).
        row, new_raw = rotate_refresh(
            session,
            raw,
            now,
            request.headers.get("user-agent", ""),
            client_ip(request),
        )
    except InvalidToken:
        resp = _error(401, "invalid_token")
        _clear_refresh(resp)
        return resp
    user = session.get(User, row.user_id)
    access = issue_access(session, user, row.id, now)  # type: ignore[arg-type]
    resp = JSONResponse(
        {
            "access_token": access,
            "token_type": "bearer",
            "expires_in": request.app.state.settings.access_ttl_minutes * 60,
        }
    )
    _set_refresh(resp, request, new_raw)
    return resp


@router.post("/refresh", dependencies=[Depends(rate_limit("auth", identity="ip"))])
async def refresh(request: Request, session: Session = SessionDep) -> JSONResponse:
    if request.headers.get("x-cvenom-csrf") != "1":
        return _error(403, "csrf")
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return _error(401, "invalid_token")
    if len(raw) > _MAX_REFRESH_LEN:
        resp = _error(401, "invalid_token")
        _clear_refresh(resp)
        return resp
    return await run_in_threadpool(_refresh_sync, session, request, raw)


# ---------------------------------------------------------------- logout / me


@router.post("/logout")
def logout(
    request: Request,
    user: User = Depends(require_user),
    session: Session = SessionDep,
) -> Response:
    row = session.get(UserSession, request.state.claims.sid)
    if row is not None and row.user_id == user.id and row.revoked_at is None:
        row.revoked_at = _now()
        session.flush()
    resp = Response(status_code=204)
    _clear_refresh(resp)
    return resp


@router.get("/me")
def me(user: User = Depends(require_user)) -> dict:
    return _user_json(user)


# ---------------------------------------------------------------- sessions


@router.get("/sessions")
def list_sessions(
    request: Request,
    user: User = Depends(require_user),
    session: Session = SessionDep,
) -> list[dict]:
    now = _now()
    rows = session.scalars(
        select(UserSession)
        .where(
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .order_by(UserSession.last_used_at.desc())
    ).all()
    current = request.state.claims.sid
    return [
        {
            "id": str(r.id),
            "user_agent": r.user_agent,
            "ip": r.ip,
            "created_at": r.created_at,
            "last_used_at": r.last_used_at,
            "current": r.id == current,
        }
        for r in rows
    ]


@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: str,
    user: User = Depends(require_user),
    session: Session = SessionDep,
) -> Response:
    not_found = HTTPException(status_code=404, detail={"error": "not_found"})
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise not_found from None
    row = session.get(UserSession, sid)
    if row is None or row.user_id != user.id:
        raise not_found
    if row.revoked_at is None:
        row.revoked_at = _now()
        session.flush()
    return Response(status_code=204)


# ---------------------------------------------------------------- invites


class InviteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    role: Literal["admin", "member"]


class AcceptBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(max_length=256)
    password: str = Field(max_length=1024)


@router.post("/invites", status_code=201)
def create_invite_route(
    body: InviteBody,
    admin: User = Depends(require_admin),
    session: Session = SessionDep,
) -> dict:
    now = _now()
    raw = create_invite(
        session, admin, str(body.email), body.role, INVITE_TTL_HOURS, now=now
    )
    return {"token": raw, "expires_at": now + timedelta(hours=INVITE_TTL_HOURS)}


@router.post("/invites/accept", dependencies=[Depends(rate_limit("auth", identity="ip"))])
def accept_invite_route(
    body: AcceptBody, session: Session = SessionDep
) -> JSONResponse:
    try:
        user = accept_invite(session, body.token, body.password)
    except InvalidInvite:
        return _error(400, "invalid_invite")
    except WeakPassword:
        return _error(422, "weak_password")
    return JSONResponse(_user_json(user), status_code=201)
