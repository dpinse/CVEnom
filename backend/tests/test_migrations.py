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


def test_kev_alerted_at_migration_backfill_and_model(scratch_url):
    from cvenom.models import Cve

    cfg = _cfg()
    command.upgrade(cfg, "0004")
    eng = create_engine(scratch_url)
    with eng.begin() as c:
        for cid in ("CVE-2026-0001", "CVE-2026-0002"):
            c.execute(text("insert into cve (cve_id, kev) values (:i, true)"), {"i": cid})
        c.execute(text(
            "insert into alert_event (type, cve_id, source) values "
            "('kev_added','CVE-2026-0001','cisa'), ('kev_added','CVE-2026-0001','vulncheck'), "
            "('cvss_min','CVE-2026-0002','nvd')"))
    command.upgrade(cfg, "0005")
    with eng.connect() as c:
        rows = dict(c.execute(text("select cve_id, kev_alerted_at is not null from cve")).all())
        col = c.execute(text(
            "select data_type, is_nullable, column_default from information_schema.columns "
            "where table_name='cve' and column_name='kev_alerted_at'")).one()
        cols = {r[0] for r in c.execute(text(
            "select column_name from information_schema.columns where table_name='cve'"))}
    assert rows == {"CVE-2026-0001": True, "CVE-2026-0002": False}  # only kev_added backfills
    assert tuple(col) == ("timestamp with time zone", "YES", None)
    # At 0005 the cve table is the head model minus the columns later revisions add.
    assert cols == {c.name for c in Cve.__table__.columns} - CVE_0006_COLS
    command.downgrade(cfg, "0004")
    with eng.connect() as c:
        cols = {r[0] for r in c.execute(text(
            "select column_name from information_schema.columns where table_name='cve'"))}
    eng.dispose()
    assert "kev_alerted_at" not in cols


CVE_0006_COLS = {
    "kev_name", "kev_action", "kev_due", "kev_ransomware", "kev_notes",
    "cvss_vector", "cvss_severity", "cwes", "references", "last_modified",
}


def _load_0006():
    import importlib.util

    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0006_cve_details_onion_cleanup.py"
    spec = importlib.util.spec_from_file_location("mig_0006", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _columns(conn, table):
    return {
        r[0]: (r[1], r[2], r[3], r[4])
        for r in conn.execute(text(
            "select column_name, data_type, is_nullable, column_default, character_maximum_length "
            "from information_schema.columns where table_name=:t"), {"t": table})
    }


def test_migration_0006_cleanup(scratch_url):
    from cvenom.models import Cve, Story

    mig = _load_0006()
    assert (mig.revision, mig.down_revision) == ("0006", "0005")
    cfg = _cfg()
    command.upgrade(cfg, "0005")
    eng = create_engine(scratch_url)
    stories = {
        "rl_onion": ("ransomware.live", "http://lockbitxyz.onion/post/acme"),
        "rl_site": ("ransomware.live", "https://www.acme-victim.example/"),
        "rl_permalink": ("ransomware.live", "https://www.ransomware.live/id/YWNtZQ==@lockbit"),
        "news_onion": ("THN", "http://newsabc.onion/article"),
        "news_clear": ("THN", "https://thehackernews.com/2026/11/x.html"),
    }
    geo = {
        "g_onion": ("ransomware_live", "http://lockbitxyz.onion/post/acme"),
        "g_site": ("ransomware_live", "https://www.acme-victim.example/"),
        "g_permalink": ("ransomware_live", "https://www.ransomware.live/id/YWNtZQ==@lockbit"),
        "g_other_clear": ("shodan", "https://example.com/scan"),  # not ransomware_live: untouched
        "g_null": ("ransomware_live", None),
    }
    with eng.begin() as c:
        c.execute(text("insert into cve (cve_id) values ('CVE-2026-0001')"))
        for key, (source, url) in stories.items():
            sid = c.execute(text(
                "insert into story (url, content_hash, source, title, summary, published) "
                "values (:u, :h, :s, :t, '', now()) returning id"),
                {"u": url, "h": key, "s": source, "t": key}).scalar()
            c.execute(text("insert into story_cve_link (story_id, cve_id) values (:i, 'CVE-2026-0001')"),
                      {"i": sid})
        for key, (source, url) in geo.items():
            c.execute(text(
                "insert into geo_event (source, external_id, kind, observed_at, story_url) "
                "values (:s, :e, 'victim', now(), :u)"), {"s": source, "e": key, "u": url})

    command.upgrade(cfg, "0006")
    with eng.connect() as c:
        left = {r[0] for r in c.execute(text("select title from story"))}
        links = c.execute(text("select count(*) from story_cve_link")).scalar()
        geo_rows = dict(c.execute(text("select external_id, story_url from geo_event")).all())
        cve_cols = _columns(c, "cve")
        story_cols = _columns(c, "story")
        # The Postgres ONION regex agrees with validate_http_url on the brief's URL cases.
        matches = {u: c.execute(text("select cast(:u as text) ~* :r"), {"u": u, "r": mig.ONION}).scalar()
                   for u in ("http://abcdef.onion/", "https://ABC.ONION/x", "http://abc.onion.:80/p",
                             "http://sub.abc.onion", "http://u@x.onion?q", "https://onion.example.com/",
                             "https://example.com/x.onion", "https://x.onionz.example/")}
    assert left == {"rl_permalink", "news_clear"}
    assert links == 2  # links of deleted stories cascade away
    assert geo_rows == {
        "g_onion": None, "g_site": None,
        "g_permalink": "https://www.ransomware.live/id/YWNtZQ==@lockbit",
        "g_other_clear": "https://example.com/scan", "g_null": None,
    }
    assert matches == {
        "http://abcdef.onion/": True, "https://ABC.ONION/x": True, "http://abc.onion.:80/p": True,
        "http://sub.abc.onion": True, "http://u@x.onion?q": True, "https://onion.example.com/": False,
        "https://example.com/x.onion": False, "https://x.onionz.example/": False,
    }
    # Schema matches the models (names, nullability, server defaults, types).
    assert set(cve_cols) == {col.name for col in Cve.__table__.columns}
    assert set(story_cols) == {col.name for col in Story.__table__.columns}
    for table, cols in ((Cve.__table__, cve_cols), (Story.__table__, story_cols)):
        for col in table.columns:
            assert (cols[col.name][1] == "YES") == col.nullable, col.name
    expect = {
        "kev_name": ("text", "YES", None, None), "kev_action": ("text", "YES", None, None),
        "kev_due": ("date", "YES", None, None), "kev_ransomware": ("boolean", "YES", None, None),
        "kev_notes": ("text", "YES", None, None),
        "cvss_vector": ("character varying", "YES", None, 255),
        "cvss_severity": ("character varying", "YES", None, 16),
        "last_modified": ("timestamp with time zone", "YES", None, None),
    }
    for name, want in expect.items():
        assert cve_cols[name] == want, name
    for name in ("cwes", "references"):
        assert cve_cols[name][:2] == ("jsonb", "NO") and cve_cols[name][2].startswith("'[]'"), name
    assert story_cols["details"][:2] == ("jsonb", "NO") and story_cols["details"][2].startswith("'{}'")

    command.downgrade(cfg, "0005")
    with eng.connect() as c:
        cve_after = set(_columns(c, "cve"))
        story_after = set(_columns(c, "story"))
        left_after = {r[0] for r in c.execute(text("select title from story"))}
    eng.dispose()
    assert not (CVE_0006_COLS & cve_after) and "details" not in story_after
    assert left_after == {"rl_permalink", "news_clear"}  # deleted rows are not restored


def test_migration_0006_on_empty_db(scratch_url):
    cfg = _cfg()
    command.upgrade(cfg, "0006")
    command.downgrade(cfg, "0005")
    command.upgrade(cfg, "0006")
