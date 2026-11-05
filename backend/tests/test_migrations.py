from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from tests.conftest import TEST_DATABASE_URL  # noqa: F401  (rootdir import)

SCRATCH = "cvenom_mig_test"
EXPECTED = {"ix_cve_published_brin", "ix_story_published_brin", "ix_story_cve_link_cve_id"}


@pytest.fixture
def scratch_url(monkeypatch):
    admin = create_engine(TEST_DATABASE_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH}"))
        c.execute(text(f"CREATE DATABASE {SCRATCH}"))
    url = TEST_DATABASE_URL.rsplit("/", 1)[0] + "/" + SCRATCH
    from cvenom.config import get_settings
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    yield url
    get_settings.cache_clear()
    with admin.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH}"))
    admin.dispose()


def _indexes(url):
    eng = create_engine(url)
    with eng.connect() as c:
        names = {r[0] for r in c.execute(text("select indexname from pg_indexes where schemaname='public'"))}
    eng.dispose()
    return names


def test_migration_upgrade_and_downgrade(scratch_url):
    backend = Path(__file__).resolve().parents[1]
    cfg = Config(str(backend / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend / "migrations"))
    command.upgrade(cfg, "head")
    assert EXPECTED <= _indexes(scratch_url)
    command.downgrade(cfg, "base")
    assert not (EXPECTED & _indexes(scratch_url))
