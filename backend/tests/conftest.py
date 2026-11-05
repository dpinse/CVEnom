import os

# Force the test DB: never defer to an exported DATABASE_URL (drop_all below).
TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/cvenom_test"
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
