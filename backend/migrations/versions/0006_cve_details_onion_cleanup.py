"""cve KEV/NVD detail columns, story.details, and .onion / non-permalink cleanup

Upgrade adds the columns, then runs an IRREVERSIBLE data cleanup:
  * deletes every ransomware.live story whose url is not a https://www.ransomware.live/
    permalink (a legacy row keyed on the victim's website would otherwise block the
    permalink re-ingest forever through the content_hash dedupe);
  * deletes every story whose url is a .onion url;
  * nulls geo_event.story_url when it is a .onion url, or a non-permalink url on a
    ransomware_live event.
Story deletes cascade to story_cve_link. Downgrade drops the columns only: the
deleted stories and the nulled story_url values are NOT restored.

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

# Matches an absolute URL whose host is (or ends in) .onion, with optional userinfo,
# trailing dot and port. Used with ~* (case-insensitive).
ONION = r"^[a-z][a-z0-9+.-]*://([^/?#@]*@)?[^/?#:@]*\.onion\.?(:[0-9]*)?([/?#]|$)"

_CVE_COLUMNS = (
    ("kev_name", sa.Text(), {}),
    ("kev_action", sa.Text(), {}),
    ("kev_due", sa.Date(), {}),
    ("kev_ransomware", sa.Boolean(), {}),
    ("kev_notes", sa.Text(), {}),
    ("cvss_vector", sa.String(length=255), {}),
    ("cvss_severity", sa.String(length=16), {}),
    ("cwes", postgresql.JSONB(), {"nullable": False, "server_default": "[]"}),
    ("references", postgresql.JSONB(), {"nullable": False, "server_default": "[]"}),
    ("last_modified", sa.DateTime(timezone=True), {}),
)


def upgrade() -> None:
    for name, type_, kw in _CVE_COLUMNS:
        op.add_column("cve", sa.Column(name, type_, nullable=kw.get("nullable", True),
                                       server_default=kw.get("server_default")))
    op.add_column(
        "story", sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}")
    )

    # ONION contains no quote character, so it is safe to inline as a SQL literal.
    assert "'" not in ONION
    op.execute(
        "DELETE FROM story WHERE source = 'ransomware.live' "
        "AND url NOT LIKE 'https://www.ransomware.live/%'"
    )
    op.execute(f"DELETE FROM story WHERE url ~* '{ONION}'")
    op.execute(
        f"UPDATE geo_event SET story_url = NULL "
        f"WHERE story_url ~* '{ONION}' "
        f"OR (source = 'ransomware_live' AND story_url NOT LIKE 'https://www.ransomware.live/%')"
    )


def downgrade() -> None:
    # Column drop only: rows deleted / story_url values nulled by upgrade are not restored.
    op.drop_column("story", "details")
    for name, _, _ in reversed(_CVE_COLUMNS):
        op.drop_column("cve", name)
