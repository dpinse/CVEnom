"""mandatory TOTP MFA: app_user MFA columns, mfa_ticket, mfa_recovery_code

Revision ID: 0007
Revises: 0006

NOTE (chain): this revision was written against 0005 on a parallel branch and
has been relinked to follow 0006 (cve details / .onion cleanup). Nothing here
depends on 0006's schema.

Every live session is revoked on upgrade: MFA is mandatory, so each existing
user (the first admin included) signs in again and is sent through enrollment.
"""
import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"  # follows 0006 (cve details / .onion cleanup)
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("app_user", sa.Column("mfa_secret_enc", sa.Text(), nullable=True))
    op.add_column("app_user", sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("app_user", sa.Column("mfa_last_step", sa.BigInteger(), nullable=True))

    op.create_table(
        "mfa_ticket",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("app_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enroll_secret_enc", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_mfa_ticket_user_id", "mfa_ticket", ["user_id"])
    op.create_index("ix_mfa_ticket_expires_at", "mfa_ticket", ["expires_at"])

    op.create_table(
        "mfa_recovery_code",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("app_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_code_user_hash"),
    )
    op.create_index("ix_mfa_recovery_code_user_id", "mfa_recovery_code", ["user_id"])

    # No session may outlive the switch to mandatory MFA.
    op.execute("UPDATE user_session SET revoked_at = now() WHERE revoked_at IS NULL")


def downgrade() -> None:
    op.drop_index("ix_mfa_recovery_code_user_id", table_name="mfa_recovery_code")
    op.drop_table("mfa_recovery_code")
    op.drop_index("ix_mfa_ticket_expires_at", table_name="mfa_ticket")
    op.drop_index("ix_mfa_ticket_user_id", table_name="mfa_ticket")
    op.drop_table("mfa_ticket")
    op.drop_column("app_user", "mfa_last_step")
    op.drop_column("app_user", "mfa_enabled_at")
    op.drop_column("app_user", "mfa_secret_enc")
