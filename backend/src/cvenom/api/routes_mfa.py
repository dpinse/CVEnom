"""Mandatory TOTP MFA: the second sign-in step, enrollment, and the account endpoints.

POST /api/auth/login (routes_auth) returns a ticket, never a session. The ticket is
exchanged here, with a TOTP or recovery code, for the access token and refresh cookie.

Every failed second factor - unknown, expired, used or foreign ticket, wrong or
replayed code, wrong state (enrolled / not enrolled) - answers with the SAME 401
bytes. Failures are raised (never returned) so the request's transaction rolls back.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from cvenom.auth import mfa
from cvenom.models import MfaTicket, User

from .deps import SessionDep, client_ip, require_user
from .ratelimit import rate_limit, reserve_mfa_attempt
from .routes_auth import session_response

router = APIRouter(prefix="/api/auth/mfa")

# Per-IP request limiter (fail closed) on every ticket route; verify/finish also
# reserve a failed-code attempt per IP and per user (ratelimit.MfaAttempt).
_TICKET_LIMIT = Depends(rate_limit("auth", identity="ip"))


def _now() -> datetime:
    return datetime.now(UTC)


def _fail() -> NoReturn:
    raise HTTPException(status_code=401, detail={"error": "invalid_mfa"})


class TicketBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: str = Field(max_length=256)


class CodeBody(TicketBody):
    code: str = Field(max_length=64)


def _load(session: Session, raw: str, now: datetime) -> tuple[MfaTicket, User]:
    try:
        return mfa.load_ticket(session, raw, now)
    except mfa.MfaFailed:
        _fail()


# ---------------------------------------------------------------- verify


def _verify_sync(session: Session, request: Request, ticket: MfaTicket, user: User,
                 code: str, now: datetime) -> JSONResponse:
    try:
        mfa.verify_second_factor(session, ticket, user, code, now)
    except mfa.MfaFailed:
        _fail()
    return session_response(session, request, user, now)


@router.post("/verify", dependencies=[_TICKET_LIMIT])
async def verify(request: Request, body: CodeBody, session: Session = SessionDep) -> JSONResponse:
    attempt = await reserve_mfa_attempt(request, ip=client_ip(request))  # before any DB work
    now = _now()
    ticket, user = await run_in_threadpool(_load, session, body.ticket, now)
    await attempt.add_user(user.id)
    resp = await run_in_threadpool(_verify_sync, session, request, ticket, user, body.code, now)
    await attempt.refund()
    return resp


# ---------------------------------------------------------------- enrollment


@router.post("/enroll/start", dependencies=[_TICKET_LIMIT])
def enroll_start(body: TicketBody, session: Session = SessionDep) -> dict:
    ticket, user = _load(session, body.ticket, _now())
    try:
        secret, uri = mfa.start_enrollment(session, ticket, user)
    except mfa.MfaFailed:
        _fail()
    return {"secret": secret, "otpauth_uri": uri}


def _finish_sync(session: Session, request: Request, ticket: MfaTicket, user: User,
                 code: str, now: datetime) -> JSONResponse:
    try:
        codes = mfa.finish_enrollment(session, ticket, user, code, now)
    except mfa.MfaFailed:
        _fail()
    return session_response(session, request, user, now, {"recovery_codes": codes})


@router.post("/enroll/finish", dependencies=[_TICKET_LIMIT])
async def enroll_finish(
    request: Request, body: CodeBody, session: Session = SessionDep
) -> JSONResponse:
    attempt = await reserve_mfa_attempt(request, ip=client_ip(request))  # before any DB work
    now = _now()
    ticket, user = await run_in_threadpool(_load, session, body.ticket, now)
    await attempt.add_user(user.id)
    resp = await run_in_threadpool(_finish_sync, session, request, ticket, user, body.code, now)
    await attempt.refund()
    return resp


# ---------------------------------------------------------------- account (signed in)

_API_LIMIT = Depends(rate_limit("api"))  # runs before require_user (see test_limiter_order)


@router.get("", dependencies=[_API_LIMIT])
def status(user: User = Depends(require_user), session: Session = SessionDep) -> dict:
    """Two-factor status for the signed-in user. Never includes the secret."""
    return {
        "enabled": mfa.is_enrolled(user),
        "enrolled_at": user.mfa_enabled_at,
        "recovery_codes_remaining": mfa.recovery_codes_remaining(session, user),
    }


class RegenerateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(max_length=64)


def _regenerate_sync(session: Session, user_id: int, code: str, now: datetime) -> list[str]:
    try:
        return mfa.regenerate_recovery_codes(session, user_id, code, now)
    except mfa.MfaFailed:
        # 403, not 401: the access token is fine, so the client must not refresh or sign out.
        raise HTTPException(status_code=403, detail={"error": "invalid_code"}) from None


@router.post("/recovery-codes", dependencies=[_API_LIMIT])
async def regenerate_recovery_codes(
    request: Request,
    body: RegenerateBody,
    user: User = Depends(require_user),
    session: Session = SessionDep,
) -> dict:
    """New recovery codes (old ones stop working). Needs a current TOTP code."""
    attempt = await reserve_mfa_attempt(request, ip=client_ip(request))
    await attempt.add_user(user.id)
    codes = await run_in_threadpool(_regenerate_sync, session, user.id, body.code, _now())
    await attempt.refund()
    return {"recovery_codes": codes}
