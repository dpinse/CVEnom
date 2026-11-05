"""invite purpose (invite|reset) and created_at

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "invite",
        sa.Column("purpose", sa.String(length=16), nullable=False, server_default="invite"),
    )
    op.add_column(
        "invite",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_check_constraint("ck_invite_purpose", "invite", "purpose in ('invite','reset')")


def downgrade() -> None:
    # A reset row must not survive as a plain invite.
    op.execute("DELETE FROM invite WHERE purpose = 'reset'")
    op.drop_constraint("ck_invite_purpose", "invite", type_="check")
    op.drop_column("invite", "created_at")
    op.drop_column("invite", "purpose")
