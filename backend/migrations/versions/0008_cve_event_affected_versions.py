"""cve_event timeline table and cve.affected_versions

Revision ID: 0008
Revises: 0007

Backfills the events derivable from existing rows: published, kev_added and
first_news (the earliest linked story per CVE).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cve", sa.Column("affected_versions", JSONB(), nullable=False,
                                   server_default=sa.text("'[]'::jsonb")))
    op.create_table(
        "cve_event",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(), sa.ForeignKey("cve.cve_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("detail", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("cve_id", "kind", "source", name="uq_cve_event_cve_kind_source"),
    )
    op.create_index("ix_cve_event_kind_occurred_at", "cve_event", ["kind", "occurred_at"])

    op.execute("""
        INSERT INTO cve_event (cve_id, kind, occurred_at, source)
        SELECT cve_id, 'published', published, 'NVD' FROM cve WHERE published IS NOT NULL
        ON CONFLICT DO NOTHING
    """)
    op.execute("""
        INSERT INTO cve_event (cve_id, kind, occurred_at, source)
        SELECT cve_id, 'kev_added', kev_added::timestamp AT TIME ZONE 'UTC',
               CASE kev_source WHEN 'cisa' THEN 'CISA KEV'
                               WHEN 'vulncheck' THEN 'VulnCheck KEV' ELSE 'KEV' END
        FROM cve WHERE kev AND kev_added IS NOT NULL
        ON CONFLICT DO NOTHING
    """)
    op.execute("""
        INSERT INTO cve_event (cve_id, kind, occurred_at, source, detail)
        SELECT DISTINCT ON (l.cve_id) l.cve_id, 'first_news', s.published, left(s.source, 64),
               jsonb_build_object('title', s.title, 'url', s.url)
        FROM story_cve_link l JOIN story s ON s.id = l.story_id
        ORDER BY l.cve_id, s.published, s.id
        ON CONFLICT DO NOTHING
    """)


def downgrade() -> None:
    op.drop_index("ix_cve_event_kind_occurred_at", table_name="cve_event")
    op.drop_table("cve_event")
    op.drop_column("cve", "affected_versions")
