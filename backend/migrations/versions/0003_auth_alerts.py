"""auth, alert and outbox tables

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _ts(name, **kw):
    return sa.Column(name, sa.DateTime(timezone=True), **kw)


def _created_at():
    return _ts("created_at", nullable=False, server_default=sa.func.now())


def upgrade() -> None:
    op.create_table(
        "app_user",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        _created_at(),
        sa.UniqueConstraint("email", name="app_user_email_key"),
        sa.CheckConstraint("role in ('admin','member')", name="ck_app_user_role"),
        sa.CheckConstraint("email = lower(email)", name="ck_app_user_email_lower"),
    )
    op.create_table(
        "invite",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        _ts("expires_at", nullable=False),
        _ts("used_at"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("app_user.id", ondelete="SET NULL")),
        sa.UniqueConstraint("token_hash", name="invite_token_hash_key"),
        sa.CheckConstraint("role in ('admin','member')", name="ck_invite_role"),
        sa.CheckConstraint("email = lower(email)", name="ck_invite_email_lower"),
    )
    op.create_table(
        "user_session",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("app_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("refresh_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_refresh_hash", sa.String(length=64)),
        sa.Column("user_agent", sa.String(length=512)),
        sa.Column("ip", sa.String(length=64)),
        _created_at(),
        _ts("last_used_at", nullable=False, server_default=sa.func.now()),
        _ts("expires_at", nullable=False),
        _ts("revoked_at"),
        sa.UniqueConstraint("refresh_hash", name="user_session_refresh_hash_key"),
    )
    op.create_index("ix_user_session_user_id", "user_session", ["user_id"])
    op.create_index("ix_user_session_prev_refresh_hash", "user_session", ["prev_refresh_hash"])
    op.create_table(
        "signing_key",
        sa.Column("kid", sa.String(length=64), primary_key=True),
        sa.Column("private_enc", sa.Text(), nullable=False),
        sa.Column("public_pem", sa.Text(), nullable=False),
        _created_at(),
        _ts("retired_at"),
    )
    op.create_table(
        "alert_event",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("cve_id", sa.String(length=32)),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        _created_at(),
        _ts("processed_at"),
    )
    op.create_index("ix_alert_event_processed_created", "alert_event", ["processed_at", "created_at"])
    op.create_index("ix_alert_event_created_at_brin", "alert_event", ["created_at"], postgresql_using="brin")
    op.create_table(
        "alert_rule",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("threshold", sa.Float()),
        sa.Column("keyword", sa.String(length=200)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("app_user.id", ondelete="SET NULL")),
        _created_at(),
        sa.CheckConstraint("kind in ('kev_added','cvss_min','epss_min','keyword')", name="ck_alert_rule_kind"),
    )
    op.create_table(
        "alert_recipient",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("alert_rule.id", ondelete="CASCADE"), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("email", sa.String(length=320)),
        sa.Column("webhook_url", sa.Text()),
        sa.Column("webhook_secret_enc", sa.Text()),
        sa.CheckConstraint("channel in ('email','webhook')", name="ck_alert_recipient_channel"),
    )
    op.create_index("ix_alert_recipient_rule_id", "alert_recipient", ["rule_id"])
    op.create_table(
        "alert_delivery",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("alert_event.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("alert_rule.id", ondelete="CASCADE"), nullable=False),
        sa.Column("recipient_id", sa.Integer(), sa.ForeignKey("alert_recipient.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text()),
        _created_at(),
        _ts("sent_at"),
        _ts("next_attempt_at"),
        sa.UniqueConstraint("rule_id", "recipient_id", "cve_id", name="uq_alert_delivery_rule_recipient_cve"),
        sa.CheckConstraint("status in ('pending','sent','failed')", name="ck_alert_delivery_status"),
    )
    op.create_index("ix_alert_delivery_status_next_attempt", "alert_delivery", ["status", "next_attempt_at"])
    op.create_index("ix_alert_delivery_event_id", "alert_delivery", ["event_id"])
    op.create_index("ix_alert_delivery_recipient_id", "alert_delivery", ["recipient_id"])


def downgrade() -> None:
    op.drop_table("alert_delivery")  # drops its indexes with it
    op.drop_table("alert_recipient")
    op.drop_table("alert_rule")
    op.drop_table("alert_event")
    op.drop_table("signing_key")
    op.drop_table("user_session")
    op.drop_table("invite")
    op.drop_table("app_user")
