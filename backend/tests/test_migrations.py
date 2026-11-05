from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from tests.conftest import TEST_DATABASE_URL  # noqa: F401  (rootdir import)

SCRATCH = "cvenom_mig_test"
EXPECTED = {"ix_cve_published_brin", "ix_story_published_brin", "ix_story_cve_link_cve_id"}
GEO_EXPECTED = {
    "ix_story_content_hash",
    "ix_geo_event_observed_at_brin",
    "ix_geo_event_country_kind",
    "uq_geo_event_source_external_id",
}


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
    assert (EXPECTED | GEO_EXPECTED) <= _indexes(scratch_url)
    command.downgrade(cfg, "0001")
    after = _indexes(scratch_url)
    assert EXPECTED <= after
    assert not (GEO_EXPECTED & after)
    command.downgrade(cfg, "base")
    assert not (EXPECTED & _indexes(scratch_url))


AUTH_TABLES = ["app_user", "invite", "user_session", "user_session_used_refresh", "signing_key", "alert_event",
               "alert_rule", "alert_recipient", "alert_delivery"]
AUTH_EXPECTED = {
    "ix_alert_event_processed_created", "ix_alert_event_created_at_brin",
    "ix_alert_delivery_status_next_attempt", "uq_alert_delivery_rule_recipient_cve",
}


def _tables(url):
    eng = create_engine(url)
    with eng.connect() as c:
        names = {r[0] for r in c.execute(text("select tablename from pg_tables where schemaname='public'"))}
    eng.dispose()
    return names


def _cfg():
    backend = Path(__file__).resolve().parents[1]
    cfg = Config(str(backend / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend / "migrations"))
    return cfg


def test_auth_migration_up_down(scratch_url):
    cfg = _cfg()
    command.upgrade(cfg, "head")
    assert set(AUTH_TABLES) <= _tables(scratch_url)
    assert AUTH_EXPECTED <= _indexes(scratch_url)
    eng = create_engine(scratch_url)
    with eng.connect() as c:
        uq = {r[0] for r in c.execute(text("select conname from pg_constraint where contype='u'"))}
    eng.dispose()
    assert "uq_alert_delivery_rule_recipient_cve" in uq
    command.downgrade(cfg, "0002")
    assert not (set(AUTH_TABLES) & _tables(scratch_url))
    assert "geo_event" in _tables(scratch_url)


def test_auth_migration_matches_models(scratch_url):
    from cvenom.models import Base

    command.upgrade(_cfg(), "head")
    eng = create_engine(scratch_url)
    with eng.connect() as c:
        for name in AUTH_TABLES:
            table = Base.metadata.tables[name]
            cols = {
                r[0]: (r[1], r[2], r[3])
                for r in c.execute(text(
                    "select column_name, data_type, is_nullable, column_default "
                    "from information_schema.columns where table_name=:t"), {"t": name})
            }
            assert set(cols) == {col.name for col in table.columns}, name
            for col in table.columns:
                assert (cols[col.name][1] == "YES") == col.nullable, (name, col.name)
                if not col.primary_key:  # serial PKs carry an implicit nextval default
                    assert (cols[col.name][2] is not None) == (col.server_default is not None), (
                        name, col.name)
                dt = col.type.compile(dialect=eng.dialect).lower()
                got = cols[col.name][0]
                if dt.startswith("varchar"):
                    assert got == "character varying", (name, col.name)
                elif dt in ("timestamp with time zone", "jsonb", "uuid", "boolean", "integer",
                            "float", "text"):
                    expect = {"float": "double precision"}.get(dt, dt)
                    assert got == expect, (name, col.name, got)
            mig_idx = {r[0] for r in c.execute(text(
                "select indexname from pg_indexes where tablename=:t"), {"t": name})}
            assert {i.name for i in table.indexes} <= mig_idx, name
            mig_fk = c.execute(text(
                "select count(*) from pg_constraint where contype='f' "
                "and conrelid = cast(:t as regclass)"), {"t": name}).scalar()
            assert mig_fk == len({fk.constraint for fk in table.foreign_keys}), name
            mig_ondelete = sorted(r[0] for r in c.execute(text(
                "select confdeltype from pg_constraint where contype='f' "
                "and conrelid = cast(:t as regclass)"), {"t": name}))
            code = {"CASCADE": "c", "SET NULL": "n"}
            model_ondelete = sorted(code[fk.ondelete] for fk in table.foreign_keys)
            assert mig_ondelete == model_ondelete, name
            mig_ck = {r[0] for r in c.execute(text(
                "select conname from pg_constraint where contype='c' "
                "and conrelid = cast(:t as regclass)"), {"t": name})}
            model_ck = {x.name for x in table.constraints if x.__class__.__name__ == "CheckConstraint"}
            assert model_ck == mig_ck, name
            mig_uq = {r[0] for r in c.execute(text(
                "select conname from pg_constraint where contype='u' "
                "and conrelid = cast(:t as regclass)"), {"t": name})}
            model_uq = {x.name for x in table.constraints
                        if x.__class__.__name__ == "UniqueConstraint" and x.name}
            assert model_uq <= mig_uq, name
    eng.dispose()


def test_geo_migration_matches_model(scratch_url):
    from cvenom.models import GeoEvent

    backend = Path(__file__).resolve().parents[1]
    cfg = Config(str(backend / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend / "migrations"))
    command.upgrade(cfg, "head")
    eng = create_engine(scratch_url)
    with eng.connect() as c:
        cols = {
            r[0]: (r[1], r[2], r[3])
            for r in c.execute(text(
                "select column_name, data_type, is_nullable, column_default from information_schema.columns "
                "where table_name='geo_event'"))
        }
    eng.dispose()
    assert set(cols) == {c.name for c in GeoEvent.__table__.columns}
    for c in GeoEvent.__table__.columns:
        assert (cols[c.name][1] == "YES") == c.nullable, c.name
    assert cols["asn"][0] == "bigint"
    assert "now()" in cols["first_seen"][2]
    assert cols["magnitude"][2].startswith("'1'")
    assert cols["details"][2].startswith("'{}'")


def test_invite_purpose_migration(scratch_url):
    from sqlalchemy.exc import IntegrityError

    cfg = _cfg()
    command.upgrade(cfg, "0003")
    eng = create_engine(scratch_url)
    with eng.begin() as c:
        c.execute(text(
            "insert into invite (email, role, token_hash, expires_at) "
            "values ('old@example.com','member','h1', now())"))
    command.upgrade(cfg, "0004")
    with eng.begin() as c:
        row = c.execute(text("select purpose, created_at is not null from invite")).one()
        assert tuple(row) == ("invite", True)
        c.execute(text(
            "insert into invite (email, role, token_hash, expires_at, purpose) "
            "values ('r@example.com','member','h2', now(), 'reset')"))
    with pytest.raises(IntegrityError):
        with eng.begin() as c:
            c.execute(text(
                "insert into invite (email, role, token_hash, expires_at, purpose) "
                "values ('x@example.com','member','h3', now(), 'bogus')"))
    command.downgrade(cfg, "0003")
    with eng.connect() as c:
        cols = {r[0] for r in c.execute(text(
            "select column_name from information_schema.columns where table_name='invite'"))}
        left = c.execute(text("select email from invite")).scalars().all()
    eng.dispose()
    assert "purpose" not in cols and "created_at" not in cols
    assert left == ["old@example.com"]  # reset invites are dropped on downgrade
