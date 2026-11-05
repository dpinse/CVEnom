"""Alert rules and recipients API. Webhook secrets are encrypted and shown once."""

from __future__ import annotations

import secrets
from typing import Annotated, Literal, NoReturn
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from cvenom import secretbox
from cvenom.alerts.rules import RuleInvalid, validate_rule
from cvenom.alerts.webhook import DEFAULT_PORT, UnsafeWebhookURL, validate_url
from cvenom.models import AlertRecipient, AlertRule, User

from .deps import SessionDep, require_admin, require_user
from .ratelimit import rate_limit

router = APIRouter(prefix="/api/alerts", dependencies=[Depends(rate_limit("api"))])

MAX_RECIPIENTS = 20
MAX_ID = 2**31 - 1
Kind = Literal["kev_added", "cvss_min", "epss_min", "keyword"]
Name = Annotated[str, StringConstraints(min_length=1, max_length=200)]


class EmailRecipientIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal["email"]
    email: EmailStr


class WebhookRecipientIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal["webhook"]
    url: str = Field(max_length=4096)
    secret: str | None = Field(default=None, min_length=16, max_length=256)


RecipientIn = Annotated[EmailRecipientIn | WebhookRecipientIn, Field(discriminator="channel")]


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name
    kind: Kind
    threshold: float | None = None
    keyword: str | None = Field(default=None, max_length=1000)
    enabled: bool = True
    recipients: list[RecipientIn] = Field(min_length=1, max_length=MAX_RECIPIENTS)

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        return _no_control(v)

    @model_validator(mode="after")
    def _check(self) -> RuleCreate:
        try:
            self.threshold, self.keyword = validate_rule(self.kind, self.threshold, self.keyword)
        except RuleInvalid:
            raise ValueError("invalid rule") from None
        return self


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name | None = None
    threshold: float | None = None
    keyword: str | None = Field(default=None, max_length=1000)
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str | None) -> str | None:
        return v if v is None else _no_control(v)


def _error(status: int, error: str) -> NoReturn:
    # Raise (never return): a returned response lets session_scope commit prior writes.
    raise HTTPException(status_code=status, detail={"error": error})


def _no_control(v: str) -> str:
    if any(ord(c) < 0x20 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F for c in v):
        raise ValueError("invalid value")
    return v


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "not_found"})


def mask_url(url: str) -> str:
    p = urlsplit(url)
    host = p.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{p.port}" if p.port and p.port != DEFAULT_PORT else ""
    return f"{p.scheme}://{host}{port}/…"


def _recipient_json(r: AlertRecipient) -> dict:
    out: dict = {"id": r.id, "channel": r.channel}
    if r.channel == "email":
        out["email"] = r.email
    elif r.webhook_url:
        try:
            out["url_masked"] = mask_url(secretbox.decrypt(r.webhook_url).decode())
        except Exception:  # key mismatch / corrupt row: never 500 a listing
            out["url_masked"] = "https://(unavailable)/\u2026"
    return out


def _rule_json(session: Session, rule: AlertRule) -> dict:
    recips = session.scalars(
        select(AlertRecipient).where(AlertRecipient.rule_id == rule.id).order_by(AlertRecipient.id)
    ).all()
    return jsonable_encoder(
        {
            "id": rule.id,
            "name": rule.name,
            "kind": rule.kind,
            "threshold": rule.threshold,
            "keyword": rule.keyword,
            "enabled": rule.enabled,
            "created_at": rule.created_at,
            "recipients": [_recipient_json(r) for r in recips],
        }
    )


def _build_recipient(
    body: EmailRecipientIn | WebhookRecipientIn,
) -> tuple[AlertRecipient, str | None]:
    """Return (unattached row, one-time secret or None); raises HTTPException(422).

    Resolves DNS exactly once (blocking: callers are sync handlers)."""
    if isinstance(body, EmailRecipientIn):
        return AlertRecipient(channel="email", email=str(body.email).lower()), None
    try:
        validate_url(body.url)
    except UnsafeWebhookURL:
        _error(422, "unsafe_webhook_url")
    secret = body.secret or secrets.token_urlsafe(32)
    row = AlertRecipient(
        channel="webhook",
        webhook_url=secretbox.encrypt(body.url.encode()),
        webhook_secret_enc=secretbox.encrypt(secret.encode()),
    )
    return row, secret


def _get_rule(session: Session, rule_id: int, *, lock: bool = False) -> AlertRule:
    rule = (
        session.get(AlertRule, rule_id, with_for_update=lock)
        if 0 < rule_id <= MAX_ID
        else None
    )
    if rule is None:
        raise _not_found()
    return rule


@router.get("/rules")
def list_rules(user: User = Depends(require_user), session: Session = SessionDep) -> list[dict]:
    rules = session.scalars(select(AlertRule).order_by(AlertRule.id)).all()
    return [_rule_json(session, r) for r in rules]


@router.get("/rules/{rule_id}")
def get_rule(
    rule_id: int, user: User = Depends(require_user), session: Session = SessionDep
) -> dict:
    return _rule_json(session, _get_rule(session, rule_id))


@router.post("/rules", status_code=201)
def create_rule(
    body: RuleCreate, admin: User = Depends(require_admin), session: Session = SessionDep
):
    # Resolve/validate every URL once and build all rows BEFORE any write.
    built = [_build_recipient(r) for r in body.recipients]
    rule = AlertRule(
        name=body.name,
        kind=body.kind,
        threshold=body.threshold,
        keyword=body.keyword,
        enabled=body.enabled,
        created_by=admin.id,
    )
    session.add(rule)
    session.flush()
    new_secrets: dict[int, str] = {}  # recipient id -> one-time secret
    for row, secret in built:
        row.rule_id = rule.id
        session.add(row)
        session.flush()
        if secret is not None:
            new_secrets[row.id] = secret
    session.refresh(rule)
    out = _rule_json(session, rule)
    for rj in out["recipients"]:
        if rj["id"] in new_secrets:
            rj["secret"] = new_secrets[rj["id"]]
    return JSONResponse(out, status_code=201)


@router.patch("/rules/{rule_id}")
def patch_rule(
    rule_id: int,
    body: RulePatch,
    admin: User = Depends(require_admin),
    session: Session = SessionDep,
):
    rule = _get_rule(session, rule_id)
    fields = body.model_fields_set
    if ("name" in fields and body.name is None) or ("enabled" in fields and body.enabled is None):
        return _error(422, "validation_error")
    threshold = body.threshold if "threshold" in fields else rule.threshold
    keyword = body.keyword if "keyword" in fields else rule.keyword
    try:
        threshold, keyword = validate_rule(rule.kind, threshold, keyword)
    except RuleInvalid:
        return _error(422, "validation_error")
    if "name" in fields:
        rule.name = body.name
    if "enabled" in fields:
        rule.enabled = body.enabled
    rule.threshold, rule.keyword = threshold, keyword
    session.flush()
    return _rule_json(session, rule)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: int, admin: User = Depends(require_admin), session: Session = SessionDep
) -> Response:
    rule = _get_rule(session, rule_id)
    session.delete(rule)
    session.flush()
    return Response(status_code=204)


@router.post("/rules/{rule_id}/recipients", status_code=201)
def add_recipient(
    rule_id: int,
    body: RecipientIn,
    admin: User = Depends(require_admin),
    session: Session = SessionDep,
):
    rule = _get_rule(session, rule_id, lock=True)  # serialize concurrent adds (cap race)
    existing = session.scalars(
        select(AlertRecipient.id).where(AlertRecipient.rule_id == rule.id)
    ).all()
    if len(existing) >= MAX_RECIPIENTS:
        return _error(422, "too_many_recipients")
    row, secret = _build_recipient(body)
    row.rule_id = rule.id
    session.add(row)
    session.flush()
    out = _recipient_json(row)
    if secret is not None:
        out["secret"] = secret
    return JSONResponse(out, status_code=201)


@router.delete("/rules/{rule_id}/recipients/{recipient_id}", status_code=204)
def delete_recipient(
    rule_id: int,
    recipient_id: int,
    admin: User = Depends(require_admin),
    session: Session = SessionDep,
) -> Response:
    rule = _get_rule(session, rule_id)
    row = session.get(AlertRecipient, recipient_id) if 0 < recipient_id <= MAX_ID else None
    if row is None or row.rule_id != rule.id:
        raise _not_found()
    session.delete(row)
    session.flush()
    return Response(status_code=204)
