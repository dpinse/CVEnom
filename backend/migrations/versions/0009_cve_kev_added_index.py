"""partial index on cve(kev_added) for KEV rows (Situation gauge and lane windows)

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_cve_kev_added", "cve", ["kev_added"], postgresql_where=sa.text("kev"))


def downgrade() -> None:
    op.drop_index("ix_cve_kev_added", table_name="cve")
