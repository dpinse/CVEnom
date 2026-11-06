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
    # First time a kev_added alert event was persisted for this CVE (NULL = never alerted).
    kev_alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    poc_badge: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    patch_available: Mapped[bool | None] = mapped_column(Boolean)
    affected: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    summary: Mapped[str] = mapped_column(Text, default="", server_default="")
    # KEV catalog detail (CISA preferred over VulnCheck) and NVD detail (migration 0006).
    kev_name: Mapped[str | None] = mapped_column(Text)
    kev_action: Mapped[str | None] = mapped_column(Text)
    kev_due: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[bool | None] = mapped_column(Boolean)
    kev_notes: Mapped[str | None] = mapped_column(Text)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cvss_severity: Mapped[str | None] = mapped_column(String(16))
    cwes: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    # "references" is a reserved word: SQLAlchemy quotes it; raw SQL must write "references".
    references: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    last_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Product/version ranges from OSV/NVD (migration 0008); see cvenom.ranges.
    affected_versions: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_cve_published_brin", "published", postgresql_using="brin"),
    )


class CveEvent(Base):
    __tablename__ = "cve_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String, ForeignKey("cve.cve_id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("cve_id", "kind", "source", name="uq_cve_event_cve_kind_source"),
        Index("ix_cve_event_kind_occurred_at", "kind", "occurred_at"),
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
    # Source context (e.g. ransomware.live victim detail); outlives the geo_event retention.
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
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
    # Mandatory TOTP MFA. The secret is secretbox-encrypted (AES-256-GCM) and never
    # returned after enrollment. NULL mfa_enabled_at = must enroll at next sign-in.
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text)
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Last accepted TOTP time step: that step and every earlier one are rejected (replay).
    mfa_last_step: Mapped[int | None] = mapped_column(BigInteger)

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
    purpose: Mapped[str] = mapped_column(
        String(16), default="invite", server_default="invite"
    )  # 'invite' creates an account; 'reset' sets an existing user's password
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("purpose in ('invite','reset')", name="ck_invite_purpose"),
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


class MfaTicket(Base):
    """Short-lived, single-use proof that the password step passed.

    Only the SHA-256 of the ticket is stored. A ticket never grants a session by
    itself: it is exchanged, together with a TOTP or recovery code, for one.
    `enroll_secret_enc` holds the pending (not yet confirmed) TOTP secret during
    enrollment, encrypted with the secret box."""

    __tablename__ = "mfa_ticket"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("app_user.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    enroll_secret_enc: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_mfa_ticket_user_id", "user_id"),
        Index("ix_mfa_ticket_expires_at", "expires_at"),
    )


class MfaRecoveryCode(Base):
    """One-time recovery code, stored as SHA-256 of its normalized form (80-bit codes)."""

    __tablename__ = "mfa_recovery_code"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("app_user.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(64))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_code_user_hash"),
        Index("ix_mfa_recovery_code_user_id", "user_id"),
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
