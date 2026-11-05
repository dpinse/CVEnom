"""geo events and story content_hash index

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_story_content_hash", "story", ["content_hash"])
    op.create_table(
        "geo_event",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("external_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("country_code", sa.String(length=2)),
        sa.Column("asn", sa.BigInteger()),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("magnitude", sa.Float(), nullable=False, server_default="1"),
        sa.Column("label", sa.Text()),
        sa.Column("cve_id", sa.String()),
        sa.Column("story_url", sa.String()),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.UniqueConstraint("source", "external_id", name="uq_geo_event_source_external_id"),
    )
    op.create_index("ix_geo_event_observed_at_brin", "geo_event", ["observed_at"], postgresql_using="brin")
    op.create_index("ix_geo_event_country_kind", "geo_event", ["country_code", "kind"])


def downgrade() -> None:
    op.drop_index("ix_geo_event_country_kind", table_name="geo_event")
    op.drop_index("ix_geo_event_observed_at_brin", table_name="geo_event")
    op.drop_table("geo_event")
    op.drop_index("ix_story_content_hash", table_name="story")
