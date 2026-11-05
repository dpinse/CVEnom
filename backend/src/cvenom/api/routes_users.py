"""Admin user management, own-password change, reset tokens and invite administration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cvenom.auth.passwords import WeakPassword, hash_password, verify_password
from cvenom.auth.users import (
    LastAdmin,
    consume_resets,
    create_reset,
    revoke_sessions,
    update_user,
)
from cvenom.models import Invite, User, UserSession

from .deps import SessionDep, require_admin, require_user
from .ratelimit import enforce_login_limits, rate_limit

# Router-level limiter dependencies run before each endpoint's own auth dependency.
router = APIRouter(prefix="/api/auth", dependencies=[Depends(rate_limit("api"))])

MAX_ID = 2**31 - 1
RESET_TTL_HOURS = 24


def _now() -> datetime:
    return datetime.now(UTC)


def _error(status: int, error: str) -> NoReturn:
    # Raise (never return): a returned response lets session_scope commit prior writes.
    raise HTTPException(status_code=status, detail={"error": error})


def _get_user(session: Session, user_id: int) -> User:
    user = session.get(User, user_id) if 0 < user_id <= MAX_ID else None
    if user is None:
        _error(404, "not_found")
    return user


def _user_json(u: User, active_sessions: int) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at,
        "active_sessions": active_sessions,
    }


def _active_sessions(session: Session, now: datetime) -> dict[int, int]:
    rows = session.execute(
        select(UserSession.user_id, func.count())
        .where(UserSession.revoked_at.is_(None), UserSession.expires_at > now)
        .group_by(UserSession.user_id)
    ).all()
    return {uid: n for uid, n in rows}


# ---------------------------------------------------------------- users


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["admin", "member"] | None = None
    is_active: bool | None = None


@router.get("/users")
def list_users(
    admin: User = Depends(require_admin), session: Session = SessionDep
) -> list[dict]:
    counts = _active_sessions(session, _now())
    users = session.scalars(select(User).order_by(User.id)).all()
    return [_user_json(u, counts.get(u.id, 0)) for u in users]


@router.patch("/users/{user_id}")
def patch_user(
    user_id: int,
    body: UserPatch,
    admin: User = Depends(require_admin),
    session: Session = SessionDep,
) -> dict:
    fields = body.model_fields_set
    if ("role" in fields and body.role is None) or (
        "is_active" in fields and body.is_active is None
    ):
        _error(422, "validation_error")
    target = _get_user(session, user_id)
    if target.id == admin.id and (
        (body.role is not None and body.role != target.role)
        or (body.is_active is not None and body.is_active != target.is_active)
    ):
        _error(409, "cannot_modify_self")
    now = _now()
    try:
        update_user(session, target, role=body.role, is_active=body.is_active, now=now)
    except LastAdmin:
        _error(409, "last_admin")
    return _user_json(target, _active_sessions(session, now).get(target.id, 0))


@router.post("/users/{user_id}/sessions/revoke", status_code=204)
def revoke_user_sessions(
    user_id: int, admin: User = Depends(require_admin), session: Session = SessionDep
) -> Response:
    target = _get_user(session, user_id)
    revoke_sessions(session, target.id, _now())
    return Response(status_code=204)


@router.post("/users/{user_id}/reset", status_code=201)
def create_user_reset(
    user_id: int, admin: User = Depends(require_admin), session: Session = SessionDep
) -> dict:
    target = _get_user(session, user_id)
    if target.id == admin.id:
        # A reset would bypass "current password required"; use /password instead.
        _error(409, "cannot_modify_self")
    if not target.is_active:
        _error(409, "user_inactive")
    raw, expires_at = create_reset(session, admin, target, RESET_TTL_HOURS)
    return {"token": raw, "expires_at": expires_at}


# ---------------------------------------------------------------- own password


class PasswordBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)


def _change_password_sync(session: Session, user: User, sid, body: PasswordBody) -> None:
    if not verify_password(user.password_hash, body.current_password):
        _error(401, "invalid_credentials")
    try:
        new_hash = hash_password(body.new_password)  # enforces the policy
    except WeakPassword:
        _error(422, "weak_password")
    user.password_hash = new_hash
    now = _now()
    revoke_sessions(session, user.id, now, except_sid=sid)  # keep this device
    consume_resets(session, user.email, now)  # outstanding reset tokens die
    session.flush()


@router.post("/password", status_code=204)
async def change_password(
    request: Request,
    body: PasswordBody,
    user: User = Depends(require_user),
    session: Session = SessionDep,
) -> Response:
    await enforce_login_limits(request, user.email)  # before any argon2 work
    await run_in_threadpool(
        _change_password_sync, session, user, request.state.claims.sid, body
    )
    return Response(status_code=204)


# ---------------------------------------------------------------- invites


@router.get("/invites")
def list_invites(
    admin: User = Depends(require_admin), session: Session = SessionDep
) -> list[dict]:
    rows = session.scalars(
        select(Invite)
        .where(Invite.used_at.is_(None), Invite.expires_at > _now())
        .order_by(Invite.id)
    ).all()
    return [
        {
            "id": i.id,
            "email": i.email,
            "role": i.role,
            "purpose": i.purpose,
            "expires_at": i.expires_at,
            "created_at": i.created_at,
            "created_by": i.created_by,
        }
        for i in rows
    ]


@router.delete("/invites/{invite_id}", status_code=204)
def delete_invite(
    invite_id: int, admin: User = Depends(require_admin), session: Session = SessionDep
) -> Response:
    row = session.get(Invite, invite_id) if 0 < invite_id <= MAX_ID else None
    if row is None:
        _error(404, "not_found")
    session.delete(row)
    session.flush()
    return Response(status_code=204)
