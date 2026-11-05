import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates


class Base(DeclarativeBase):
    pass


class Cve(Base):
    __tablename__ = "cve"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    kev_added: Mapped[date | None] = mapped_column(Date)
    kev_source: Mapped[str | None] = mapped_column(String)
    poc_badge: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    patch_available: Mapped[bool | None] = mapped_column(Boolean)
    affected: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    summary: Mapped[str] = mapped_column(Text, default="", server_default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_cve_published_brin", "published", postgresql_using="brin"),
    )


class Story(Base):
    __tablename__ = "story"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String, unique=True)
    content_hash: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, default="", server_default="")
    published: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_story_published_brin", "published", postgresql_using="brin"),
        Index("ix_story_content_hash", "content_hash"),
    )


class StoryCveLink(Base):
    __tablename__ = "story_cve_link"

    story_id: Mapped[int] = mapped_column(
        ForeignKey("story.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cve.cve_id", ondelete="CASCADE"), primary_key=True
    )


Index("ix_story_cve_link_cve_id", StoryCveLink.cve_id)


class CollectorRun(Base):
    __tablename__ = "collector_run"

    collector: Mapped[str] = mapped_column(String, primary_key=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")


class GeoEvent(Base):
    __tablename__ = "geo_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String)
    external_id: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    country_code: Mapped[str | None] = mapped_column(String(2))
    asn: Mapped[int | None] = mapped_column(BigInteger)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    magnitude: Mapped[float] = mapped_column(Float, default=1.0, server_default="1")
    label: Mapped[str | None] = mapped_column(Text)
    cve_id: Mapped[str | None] = mapped_column(String)  # reference only: no FK
    story_url: Mapped[str | None] = mapped_column(String)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")

    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_geo_event_source_external_id"),
        Index("ix_geo_event_observed_at_brin", "observed_at", postgresql_using="brin"),
        Index("ix_geo_event_country_kind", "country_code", "kind"),
    )


class User(Base):
    __tablename__ = "app_user"  # "user" is a reserved word in Postgres

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("role in ('admin','member')", name="ck_app_user_role"),
        CheckConstraint("email = lower(email)", name="ck_app_user_email_lower"),
    )

    @validates("email")
    def _normalize_email(self, key, value):
        return value.strip().lower() if isinstance(value, str) else value


class Invite(Base):
    __tablename__ = "invite"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("role in ('admin','member')", name="ck_invite_role"),
        CheckConstraint("email = lower(email)", name="ck_invite_email_lower"),
    )

    @validates("email")
    def _normalize_email(self, key, value):
        return value.strip().lower() if isinstance(value, str) else value


class UserSession(Base):
    __tablename__ = "user_session"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[int] = mapped_column(ForeignKey("app_user.id", ondelete="CASCADE"))
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prev_refresh_hash: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_user_session_user_id", "user_id"),
        Index("ix_user_session_prev_refresh_hash", "prev_refresh_hash"),
    )


class UserSessionUsedRefresh(Base):
    """Every refresh hash a session has rotated away from (reuse detection)."""

    __tablename__ = "user_session_used_refresh"

    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("user_session.id", ondelete="CASCADE"), index=True
    )
    used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class SigningKey(Base):
    __tablename__ = "signing_key"

    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    private_enc: Mapped[str] = mapped_column(Text)
    public_pem: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AlertEvent(Base):
    """Outbox row: written in the same transaction as the change it announces."""

    __tablename__ = "alert_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(64))
    cve_id: Mapped[str | None] = mapped_column(String(32))  # reference only: no FK
    source: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_alert_event_processed_created", "processed_at", "created_at"),
        Index("ix_alert_event_created_at_brin", "created_at", postgresql_using="brin"),
    )


class AlertRule(Base):
    __tablename__ = "alert_rule"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16))
    threshold: Mapped[float | None] = mapped_column(Float)
    keyword: Mapped[str | None] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "kind in ('kev_added','cvss_min','epss_min','keyword')", name="ck_alert_rule_kind"
        ),
    )


class AlertRecipient(Base):
    __tablename__ = "alert_recipient"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rule.id", ondelete="CASCADE"))
    channel: Mapped[str] = mapped_column(String(16))
    email: Mapped[str | None] = mapped_column(String(320))
    webhook_url: Mapped[str | None] = mapped_column(Text)
    webhook_secret_enc: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("channel in ('email','webhook')", name="ck_alert_recipient_channel"),
        Index("ix_alert_recipient_rule_id", "rule_id"),
    )


class AlertDelivery(Base):
    __tablename__ = "alert_delivery"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("alert_event.id", ondelete="CASCADE"))
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rule.id", ondelete="CASCADE"))
    recipient_id: Mapped[int] = mapped_column(
        ForeignKey("alert_recipient.id", ondelete="CASCADE")
    )
    cve_id: Mapped[str] = mapped_column(String(32))  # reference only: no FK
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "rule_id", "recipient_id", "cve_id", name="uq_alert_delivery_rule_recipient_cve"
        ),
        CheckConstraint("status in ('pending','sent','failed')", name="ck_alert_delivery_status"),
        Index("ix_alert_delivery_status_next_attempt", "status", "next_attempt_at"),
        Index("ix_alert_delivery_event_id", "event_id"),
        Index("ix_alert_delivery_recipient_id", "recipient_id"),
    )
