"""cve.kev_alerted_at: when a kev_added alert event was first persisted for the CVE

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cve", sa.Column("kev_alerted_at", sa.DateTime(timezone=True), nullable=True))
    # Existing data must not re-alert: mark every CVE that already has a kev_added event.
    op.execute(
        """
        UPDATE cve SET kev_alerted_at = ev.first_at
        FROM (
            SELECT cve_id, MIN(created_at) AS first_at
            FROM alert_event
            WHERE type = 'kev_added' AND cve_id IS NOT NULL
            GROUP BY cve_id
        ) AS ev
        WHERE cve.cve_id = ev.cve_id
        """
    )


def downgrade() -> None:
    op.drop_column("cve", "kev_alerted_at")
