"""initial schema

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve",
        sa.Column("cve_id", sa.String(), primary_key=True),
        sa.Column("published", sa.DateTime(timezone=True)),
        sa.Column("cvss", sa.Float()),
        sa.Column("epss", sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("kev_added", sa.Date()),
        sa.Column("kev_source", sa.String()),
        sa.Column("poc_badge", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("patch_available", sa.Boolean()),
        sa.Column("affected", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_cve_published_brin", "cve", ["published"], postgresql_using="brin")
    op.create_table(
        "story",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("url", sa.String(), nullable=False, unique=True),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("published", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_story_published_brin", "story", ["published"], postgresql_using="brin")
    op.create_table(
        "story_cve_link",
        sa.Column("story_id", sa.Integer(), sa.ForeignKey("story.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("cve_id", sa.String(), sa.ForeignKey("cve.cve_id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_index("ix_story_cve_link_cve_id", "story_cve_link", ["cve_id"])
    op.create_table(
        "collector_run",
        sa.Column("collector", sa.String(), primary_key=True),
        sa.Column("last_run", sa.DateTime(timezone=True)),
        sa.Column("state", postgresql.JSONB(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_table("collector_run")
    op.drop_index("ix_story_cve_link_cve_id", table_name="story_cve_link")
    op.drop_table("story_cve_link")
    op.drop_index("ix_story_published_brin", table_name="story")
    op.drop_table("story")
    op.drop_index("ix_cve_published_brin", table_name="cve")
    op.drop_table("cve")
