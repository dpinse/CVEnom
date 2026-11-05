import os

# Force the test DB: never defer to an exported DATABASE_URL (drop_all below).
# CVENOM_TEST_PG_PORT selects a different local test Postgres (parallel worktrees); the host and
# the cvenom_test database are fixed so the drop_all can never target a real database.
_port = os.environ.get("CVENOM_TEST_PG_PORT", "5432")
if not _port.isdigit():
    raise RuntimeError("CVENOM_TEST_PG_PORT must be a port number")
TEST_DATABASE_URL = f"postgresql+psycopg://postgres:postgres@localhost:{_port}/cvenom_test"
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from cvenom.models import Base


@pytest.fixture(scope="session")
def test_engine():
    engine = create_engine(TEST_DATABASE_URL)
    dbname = engine.url.database or ""
    if not dbname.endswith("_test"):
        raise RuntimeError(f"refusing to drop_all on non-test database {dbname!r}")
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(test_engine):
    """Session wrapped in an outer transaction that is rolled back per test."""
    conn = test_engine.connect()
    trans = conn.begin()
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        conn.close()


@pytest.fixture(autouse=True)
def _reset_key_cache():
    from cvenom.auth import tokens

    tokens.reset_key_cache()
    yield
    tokens.reset_key_cache()


@pytest.fixture(autouse=True)
def _no_live_publish(monkeypatch):
    """run_collector must never reach a real Redis from the test suite."""
    import cvenom.tasks

    monkeypatch.setattr(cvenom.tasks, "_publish_live", lambda what: None)
