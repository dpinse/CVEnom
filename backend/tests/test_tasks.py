from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from cvenom.collectors.base import REGISTRY, Collector, CollectorResult
from cvenom.models import Cve, CollectorRun
from cvenom.schemas import NormalizedCve


ALL_COLLECTORS = {
    "nvd", "epss", "cisa_kev", "vulncheck_kev", "osv", "news_krebs", "news_thn",
    "news_bleeping", "news_securityweek", "ransomware_live", "dshield", "cf_radar", "abusech",
    "news_talos", "news_unit42", "news_checkpoint", "news_securelist", "news_msft_security",
    "news_zdi", "news_tenable", "news_certcc", "news_ncsc_uk", "news_jvn", "news_sans_isc",
    "news_project_zero", "exploitdb", "circl_osint",
}


def test_registry_contains_exactly_all_collectors(fake_registry):
    assert {n for n in REGISTRY if not n.startswith("fake")} == ALL_COLLECTORS


def test_beat_schedule_has_entry_per_collector_and_maintenance():
    from cvenom.tasks import beat_schedule, purge_geo_task, refresh_geoip_task
    collect = {k for k in beat_schedule if k.startswith("collect-")}
    assert {k.removeprefix("collect-") for k in collect} == set(REGISTRY)
    from celery.schedules import crontab

    geo = beat_schedule["maintenance-geoip"]
    assert geo["task"] == refresh_geoip_task.name
    assert isinstance(geo["schedule"], crontab)
    assert geo["schedule"] == crontab(minute=17, hour="*/6")
    purge = beat_schedule["maintenance-purge-geo"]
    assert purge["task"] == purge_geo_task.name
    assert isinstance(purge["schedule"], crontab)
    assert purge["schedule"] == crontab(minute=23)
    assert set(beat_schedule) == collect | {"maintenance-geoip", "maintenance-purge-geo",
                                            "alerts-dispatch", "maintenance-purge-sessions"}


def test_maintenance_tasks_registered_on_celery_app():
    from cvenom.tasks import celery_app, purge_geo_task, refresh_geoip_task
    assert refresh_geoip_task.name in celery_app.tasks
    assert purge_geo_task.name in celery_app.tasks
    assert celery_app.conf.beat_schedule["maintenance-geoip"]["task"] == refresh_geoip_task.name


def test_refresh_geoip_job_success(monkeypatch):
    import cvenom.tasks as tasks
    from cvenom.config import get_settings
    calls = []

    async def fake_refresh(d, settings):
        calls.append(d)
        return "dbip"

    monkeypatch.setattr(tasks, "refresh_geoip", fake_refresh)
    lock = FakeLock()
    out = tasks.refresh_geoip_job(lock=lock)
    assert out == {"ok": True, "provider": "dbip"}
    assert calls == [get_settings().geoip_dir]
    assert lock.acquired == [("maintenance-geoip", 3600)]
    assert lock.released == ["maintenance-geoip"]


def test_refresh_geoip_job_lock_held(monkeypatch):
    import cvenom.tasks as tasks

    async def boom(*a, **k):
        raise AssertionError("should not run")

    monkeypatch.setattr(tasks, "refresh_geoip", boom)
    lock = FakeLock(held=True)
    assert tasks.refresh_geoip_job(lock=lock) == {"skipped": True}
    assert lock.released == []


def test_refresh_geoip_job_failure_is_swallowed(monkeypatch, caplog):
    import cvenom.tasks as tasks

    async def boom(*a, **k):
        raise RuntimeError("net down")

    monkeypatch.setattr(tasks, "refresh_geoip", boom)
    lock = FakeLock()
    with caplog.at_level("WARNING", logger="cvenom.tasks"):
        assert tasks.refresh_geoip_job(lock=lock) == {"ok": False}
    assert lock.released == ["maintenance-geoip"]
    assert "geoip refresh failed" in caplog.text
    assert "net down" not in caplog.text


def _seed_geo(db_session, now):
    from cvenom.models import GeoEvent
    for i, days in enumerate((200, 100, 1)):
        db_session.add(GeoEvent(source="t", external_id=f"e{i}", kind="k",
                                observed_at=now - timedelta(days=days)))
    db_session.flush()


def test_purge_geo_job_deletes_only_old(db_session, factory, monkeypatch):
    import cvenom.tasks as tasks
    from sqlalchemy import select
    from cvenom.models import GeoEvent
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    _seed_geo(db_session, now)
    monkeypatch.setattr(tasks, "get_settings", lambda: type("S", (), {"geo_retention_days": 150})())
    lock = FakeLock()
    out = tasks.purge_geo_job(session_factory=factory, lock=lock, now=now)
    assert out == {"ok": True, "deleted": 1}
    left = {e.external_id for e in db_session.scalars(select(GeoEvent))}
    assert left == {"e1", "e2"}
    assert lock.acquired == [("maintenance-purge-geo", 3600)]
    assert lock.released == ["maintenance-purge-geo"]


def test_purge_geo_job_lock_held(db_session, factory):
    import cvenom.tasks as tasks
    lock = FakeLock(held=True)
    assert tasks.purge_geo_job(session_factory=factory, lock=lock) == {"skipped": True}
    assert lock.released == []


def test_purge_geo_job_releases_lock_on_failure(db_session):
    import cvenom.tasks as tasks

    @contextmanager
    def bad():
        raise RuntimeError("db down")
        yield

    lock = FakeLock()
    with pytest.raises(RuntimeError):
        tasks.purge_geo_job(session_factory=bad, lock=lock)
    assert lock.released == ["maintenance-purge-geo"]


class FakeLock:
    def __init__(self, held=False):
        self.held = held
        self.acquired = []
        self.released = []

    def acquire(self, name, ttl):
        self.acquired.append((name, ttl))
        return not self.held

    def release(self, name):
        self.released.append(name)


@pytest.fixture
def factory(db_session):
    @contextmanager
    def f():
        yield db_session
        db_session.flush()
    return f


@pytest.fixture
def fake_registry():
    import cvenom.tasks  # noqa: F401
    added = []

    def add(cls):
        REGISTRY[cls.name] = cls
        added.append(cls.name)
        return cls

    yield add
    for n in added:
        REGISTRY.pop(n, None)


def make_fake(name="fake_t", *, fail=False, enrich=False, seen=None):
    class Fake(Collector):
        cadence_seconds = 123
        enrich_only = enrich

        async def fetch(self):
            if seen is not None:
                seen.append((self.since, dict(self.state)))
            if fail:
                raise RuntimeError("boom")
            return {}

        def normalize(self, raw):
            self.state["cursor"] = "new"
            return CollectorResult(
                cves=[NormalizedCve(cve_id="CVE-2099-0001", cvss=9.8)],
                events=[{"type": "x"}],
            )

    Fake.name = name
    return Fake


def test_run_collector_success(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    fake_registry(make_fake())
    lock = FakeLock()
    before = datetime.now(timezone.utc)
    out = run_collector("fake_t", session_factory=factory, lock=lock)
    after = datetime.now(timezone.utc)
    assert out["ok"] and not out["skipped"] and out["cves"] == 1
    assert out["events"] == [{"type": "x"}]
    row = db_session.get(CollectorRun, "fake_t")
    assert before <= row.last_run <= after
    assert row.state == {"cursor": "new"}
    assert db_session.get(Cve, "CVE-2099-0001") is not None
    assert lock.acquired == [("fake_t", 246)] and lock.released == ["fake_t"]


def test_run_collector_passes_collector_name(db_session, factory, fake_registry, monkeypatch):
    import cvenom.tasks as tasks
    fake_registry(make_fake())
    seen = {}
    real = tasks.ingest

    def spy(session, result, **kw):
        seen.update(kw)
        return real(session, result, **kw)

    monkeypatch.setattr(tasks, "ingest", spy)
    tasks.run_collector("fake_t", session_factory=factory, lock=FakeLock())
    assert seen == {"enrich_only": False, "collector": "fake_t"}


def test_run_collector_failure_does_not_advance(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    fake_registry(make_fake(fail=True))
    prior = datetime(2020, 1, 1, tzinfo=timezone.utc)
    db_session.add(CollectorRun(collector="fake_t", last_run=prior, state={"k": 1}))
    db_session.flush()
    lock = FakeLock()
    out = run_collector("fake_t", session_factory=factory, lock=lock)
    assert out["ok"] is False and out["cves"] == 0
    row = db_session.get(CollectorRun, "fake_t")
    assert row.last_run == prior and row.state == {"k": 1}
    assert db_session.get(Cve, "CVE-2099-0001") is None
    assert lock.released == ["fake_t"]


def test_run_collector_failure_without_prior_row_creates_no_advance(
    db_session, factory, fake_registry
):
    from cvenom.tasks import run_collector
    fake_registry(make_fake(fail=True))
    out = run_collector("fake_t", session_factory=factory, lock=FakeLock())
    assert out["ok"] is False
    assert db_session.get(CollectorRun, "fake_t") is None
    assert db_session.get(Cve, "CVE-2099-0001") is None


def test_run_collector_passes_since_and_state(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    seen = []
    fake_registry(make_fake(seen=seen))
    prior = datetime(2021, 5, 5, tzinfo=timezone.utc)
    db_session.add(CollectorRun(collector="fake_t", last_run=prior, state={"k": 1}))
    db_session.flush()
    before = datetime.now(timezone.utc)
    run_collector("fake_t", session_factory=factory, lock=FakeLock())
    # The window overlaps the previous one by WINDOW_OVERLAP (upserts are idempotent).
    assert seen == [(prior - timedelta(hours=1), {"k": 1})]
    # last_run is still the run's START time, not the overlapped since.
    assert db_session.get(CollectorRun, "fake_t").last_run >= before


def test_window_overlap_constant_and_first_run_since_is_none(db_session, factory, fake_registry):
    from cvenom import tasks
    assert tasks.WINDOW_OVERLAP == timedelta(hours=1)
    seen = []
    fake_registry(make_fake(seen=seen))
    tasks.run_collector("fake_t", session_factory=factory, lock=FakeLock())
    assert seen == [(None, {})]


def test_run_collector_passes_cve_count_to_enrich_only_state(db_session, factory, fake_registry):
    from sqlalchemy import func, select
    from cvenom.tasks import run_collector
    seen = []
    fake_registry(make_fake(enrich=True, seen=seen))
    expected = db_session.scalar(select(func.count()).select_from(Cve))
    run_collector("fake_t", session_factory=factory, lock=FakeLock())
    assert seen[0][1]["cve_count"] == expected


def test_run_collector_non_enrich_state_has_no_cve_count(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    seen = []
    fake_registry(make_fake(seen=seen))
    run_collector("fake_t", session_factory=factory, lock=FakeLock())
    assert "cve_count" not in seen[0][1]


def test_run_collector_enrich_only_creates_no_rows(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    fake_registry(make_fake(enrich=True))
    out = run_collector("fake_t", session_factory=factory, lock=FakeLock())
    assert out["ok"]
    assert db_session.get(Cve, "CVE-2099-0001") is None


def test_run_collector_lock_held_skips(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    seen = []
    fake_registry(make_fake(seen=seen))
    lock = FakeLock(held=True)
    out = run_collector("fake_t", session_factory=factory, lock=lock)
    assert out["skipped"] is True and out["ok"] is False
    assert seen == []
    assert db_session.get(Cve, "CVE-2099-0001") is None
    assert db_session.get(CollectorRun, "fake_t") is None
    assert lock.released == []


def test_lock_released_when_session_raises(db_session, fake_registry):
    from cvenom.tasks import run_collector
    fake_registry(make_fake())

    @contextmanager
    def bad():
        raise RuntimeError("db down")
        yield

    lock = FakeLock()
    with pytest.raises(RuntimeError):
        run_collector("fake_t", session_factory=bad, lock=lock)
    assert lock.released == ["fake_t"]


def test_redis_lock_token_semantics():
    from cvenom.tasks import RedisLock

    class FakeRedis:
        def __init__(self):
            self.d = {}

        def set(self, k, v, nx=False, ex=None):
            if nx and k in self.d:
                return None
            self.d[k] = v
            return True

        def get(self, k):
            return self.d.get(k)

        def eval(self, script, numkeys, key, token):
            assert "'del'" in script and numkeys == 1
            if self.d.get(key) == token:
                del self.d[key]
                return 1
            return 0

    r = FakeRedis()
    a, b = RedisLock(r), RedisLock(r)
    assert a.acquire("n", 10) is True
    assert b.acquire("n", 10) is False
    b.release("n")  # not the holder
    assert "cvenom:lock:n" in r.d
    a.release("n")
    assert "cvenom:lock:n" not in r.d


def test_celery_config():
    from cvenom.config import get_settings
    from cvenom.tasks import celery_app, run_collector_task
    assert celery_app.conf.broker_url == get_settings().redis_url
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.timezone == "UTC" and celery_app.conf.enable_utc
    sched = celery_app.conf.beat_schedule
    for name, cls in REGISTRY.items():
        if name.startswith("fake"):
            continue
        e = sched[f"collect-{name}"]
        assert e == {
            "task": run_collector_task.name,
            "schedule": cls.cadence_seconds,
            "args": (name,),
        }


def test_row_loaded_with_for_update(db_session, factory, fake_registry):
    from sqlalchemy import event
    from cvenom.tasks import run_collector
    fake_registry(make_fake())
    stmts = []

    def spy(conn, cursor, statement, *a):
        stmts.append(statement)

    bind = db_session.get_bind()
    event.listen(bind, "before_cursor_execute", spy)
    try:
        run_collector("fake_t", session_factory=factory, lock=FakeLock())
    finally:
        event.remove(bind, "before_cursor_execute", spy)
    sel = [s for s in stmts if "FROM collector_run" in s and s.lstrip().startswith("SELECT")]
    assert sel and all("FOR UPDATE" in s for s in sel)


def test_ingest_failure_rolls_back_and_releases_lock(db_session, fake_registry, monkeypatch):
    import cvenom.tasks as tasks
    fake_registry(make_fake())
    prior = datetime(2020, 1, 1, tzinfo=timezone.utc)
    db_session.add(CollectorRun(collector="fake_t", last_run=prior, state={"k": 1}))
    db_session.flush()

    @contextmanager
    def tx():
        sp = db_session.begin_nested()
        try:
            yield db_session
            sp.commit()
        except Exception:
            sp.rollback()
            raise

    def bad_ingest(session, result, *, enrich_only=False, collector=None):
        from cvenom.pipeline import ingest
        ingest(session, result, enrich_only=enrich_only, collector=collector)  # writes CVE rows first
        raise RuntimeError("ingest boom")

    monkeypatch.setattr(tasks, "ingest", bad_ingest)
    lock = FakeLock()
    with pytest.raises(RuntimeError, match="ingest boom"):
        tasks.run_collector("fake_t", session_factory=tx, lock=lock)
    assert lock.released == ["fake_t"]
    assert db_session.get(Cve, "CVE-2099-0001") is None
    db_session.expire_all()
    row = db_session.get(CollectorRun, "fake_t")
    assert row.last_run == prior and row.state == {"k": 1}


def test_ingest_failure_creates_no_run_row(db_session, fake_registry, monkeypatch):
    import cvenom.tasks as tasks
    fake_registry(make_fake())

    @contextmanager
    def tx():
        sp = db_session.begin_nested()
        try:
            yield db_session
            sp.commit()
        except Exception:
            sp.rollback()
            raise

    def bad_ingest(session, result, *, enrich_only=False, collector=None):
        raise RuntimeError("ingest boom")

    monkeypatch.setattr(tasks, "ingest", bad_ingest)
    with pytest.raises(RuntimeError):
        tasks.run_collector("fake_t", session_factory=tx, lock=FakeLock())
    assert db_session.get(CollectorRun, "fake_t") is None



def test_default_redis_client_is_shared_module_level_and_lazy(monkeypatch):
    import redis
    from cvenom import tasks

    created = []

    def fake_from_url(url, **kw):
        created.append(url)
        return object()

    monkeypatch.setattr(redis.Redis, "from_url", staticmethod(fake_from_url))
    monkeypatch.setattr(tasks, "_redis_client", None)
    a, b = tasks.RedisLock(), tasks.RedisLock()
    assert created == []  # lazy: nothing created until used
    assert a.client is b.client
    assert len(created) == 1  # one client (one connection pool) for all locks


def test_injected_redis_client_still_used():
    from cvenom.tasks import RedisLock
    sentinel = object()
    assert RedisLock(sentinel).client is sentinel


def test_refresh_geoip_failure_does_not_log_presigned_url(monkeypatch, caplog):
    import httpx

    import cvenom.tasks as tasks

    url = "https://r2.example/db?X-Amz-Signature=SECRETSIG"

    async def boom(*a, **k):
        req = httpx.Request("GET", url)
        raise httpx.HTTPStatusError(f"403 for {url}", request=req,
                                    response=httpx.Response(403, request=req))

    monkeypatch.setattr(tasks, "refresh_geoip", boom)
    with caplog.at_level("DEBUG"):
        assert tasks.refresh_geoip_job(lock=FakeLock()) == {"ok": False}
    assert "SECRETSIG" not in caplog.text
    assert "geoip refresh failed" in caplog.text and "403" in caplog.text


def _geoip_dir(monkeypatch, tmp_path, age_days=None, files=("country.mmdb", "asn.mmdb")):
    import os
    import time

    from cvenom.config import get_settings

    monkeypatch.setenv("GEOIP_DIR", str(tmp_path))
    get_settings.cache_clear()
    for name in files:
        f = tmp_path / name
        f.write_bytes(b"x")
        if age_days is not None:
            old = time.time() - age_days * 86400
            os.utime(f, (old, old))


@pytest.fixture
def geoip_calls(monkeypatch):
    import cvenom.tasks as tasks
    from cvenom.config import get_settings

    calls = []

    async def fake_refresh(d, settings):
        calls.append(d)
        return "dbip"

    monkeypatch.setattr(tasks, "refresh_geoip", fake_refresh)
    yield calls
    monkeypatch.undo()
    get_settings.cache_clear()


def test_refresh_geoip_job_fresh_files_skipped(monkeypatch, tmp_path, geoip_calls):
    import cvenom.tasks as tasks
    _geoip_dir(monkeypatch, tmp_path, age_days=1)
    assert tasks.refresh_geoip_job(lock=FakeLock()) == {"ok": True, "skipped": "fresh"}
    assert geoip_calls == []


@pytest.mark.parametrize("age,files", [
    (8, ("country.mmdb", "asn.mmdb")),
    (None, ()),
    (1, ("country.mmdb",)),  # ASN missing
])
def test_refresh_geoip_job_stale_or_missing_downloads(monkeypatch, tmp_path, geoip_calls, age, files):
    import cvenom.tasks as tasks
    _geoip_dir(monkeypatch, tmp_path, age_days=age, files=files)
    assert tasks.refresh_geoip_job(lock=FakeLock())["ok"] is True
    assert geoip_calls == [str(tmp_path)]


def test_refresh_geoip_job_stale_asn_alone_downloads(monkeypatch, tmp_path, geoip_calls):
    import os
    import time

    import cvenom.tasks as tasks
    _geoip_dir(monkeypatch, tmp_path, age_days=1)
    old = time.time() - 9 * 86400
    os.utime(tmp_path / "asn.mmdb", (old, old))
    tasks.refresh_geoip_job(lock=FakeLock())
    assert len(geoip_calls) == 1


def test_refresh_geoip_job_force_downloads_when_fresh(monkeypatch, tmp_path, geoip_calls):
    import cvenom.tasks as tasks
    _geoip_dir(monkeypatch, tmp_path, age_days=1)
    out = tasks.refresh_geoip_job(lock=FakeLock(), force=True)
    assert out == {"ok": True, "provider": "dbip"}
    assert len(geoip_calls) == 1


def test_worker_ready_handler_enqueues_refresh_once(monkeypatch):
    from celery.signals import worker_ready

    import cvenom.tasks as tasks

    calls = []
    monkeypatch.setattr(tasks.refresh_geoip_task, "delay", lambda: calls.append(1))
    worker_ready.send(sender=None)
    assert calls == [1]  # connected to the real signal, enqueues exactly once


def test_worker_ready_handler_swallows_errors(monkeypatch, caplog):
    import cvenom.tasks as tasks

    def boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr(tasks.refresh_geoip_task, "delay", boom)
    with caplog.at_level("WARNING", logger="cvenom.tasks"):
        tasks.bootstrap_geoip()
    assert "geoip bootstrap" in caplog.text


def _patch_bootstrap(monkeypatch, last_runs):
    from cvenom import tasks

    queued: list[str] = []
    monkeypatch.setattr(tasks, "_collector_last_runs", lambda: last_runs)
    monkeypatch.setattr(tasks.run_collector_task, "delay", lambda name: queued.append(name))
    return tasks, queued


def test_bootstrap_collectors_registered_on_worker_ready():
    from celery.signals import worker_ready

    from cvenom import tasks

    assert tasks.bootstrap_collectors in list(worker_ready._live_receivers(None))


def test_bootstrap_collectors_queues_only_stale(monkeypatch):
    from datetime import datetime, timedelta, timezone

    from cvenom import tasks

    names = sorted(tasks.REGISTRY)
    stale, fresh = names[0], names[1]
    now = datetime.now(timezone.utc)
    last_runs = {
        stale: now - timedelta(seconds=tasks.REGISTRY[stale].cadence_seconds + 60),
        fresh: now - timedelta(seconds=tasks.REGISTRY[fresh].cadence_seconds // 2),
    }
    tasks, queued = _patch_bootstrap(monkeypatch, last_runs)
    tasks.bootstrap_collectors()
    assert stale in queued
    assert fresh not in queued
    # everything with no row at all is "never run" and is queued
    assert set(queued) == set(names) - {fresh}


def test_bootstrap_collectors_queues_null_last_run(monkeypatch):
    from cvenom import tasks

    names = sorted(tasks.REGISTRY)
    tasks, queued = _patch_bootstrap(monkeypatch, {n: None for n in names})
    tasks.bootstrap_collectors()
    assert sorted(queued) == names


def test_bootstrap_collectors_survives_enqueue_failure(monkeypatch, caplog):
    from cvenom import tasks

    queued: list[str] = []

    def flaky(name):
        first = not queued
        queued.append(name)
        if first:
            raise RuntimeError("broker down")

    monkeypatch.setattr(tasks, "_collector_last_runs", lambda: {})
    monkeypatch.setattr(tasks.run_collector_task, "delay", flaky)
    with caplog.at_level("WARNING", logger="cvenom.tasks"):
        tasks.bootstrap_collectors()
    assert "collector bootstrap" in caplog.text
    assert sorted(queued) == sorted(tasks.REGISTRY)  # one failure does not stop the rest


def test_bootstrap_collectors_db_error_queues_nothing(monkeypatch, caplog):
    from cvenom import tasks

    queued: list[str] = []

    def boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(tasks, "_collector_last_runs", boom)
    monkeypatch.setattr(tasks.run_collector_task, "delay", lambda name: queued.append(name))
    with caplog.at_level("WARNING", logger="cvenom.tasks"):
        tasks.bootstrap_collectors()  # must not raise
    assert queued == []
    assert "last_run lookup failed" in caplog.text


def test_collector_last_runs_reads_all_rows(monkeypatch, db_session):
    from contextlib import contextmanager
    from datetime import datetime, timezone

    from cvenom import tasks

    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    db_session.add_all([CollectorRun(collector="fake_a", last_run=ts, state={}),
                        CollectorRun(collector="fake_b", last_run=None, state={})])
    db_session.flush()

    @contextmanager
    def scope():  # the helper normally opens its own session; reuse the test one so rows are visible
        yield db_session

    monkeypatch.setattr(tasks, "session_scope", scope)
    runs = tasks._collector_last_runs()
    assert runs["fake_a"] == ts and runs["fake_b"] is None


def test_worker_process_init_disposes_engine_without_closing(monkeypatch):
    from unittest.mock import MagicMock

    from celery.signals import worker_process_init

    from cvenom import tasks

    engine = MagicMock()
    monkeypatch.setattr(tasks, "get_engine", lambda: engine)
    assert tasks.reset_db_engine_after_fork in list(worker_process_init._live_receivers(None))
    tasks.reset_db_engine_after_fork()
    engine.dispose.assert_called_once_with(close=False)


def test_worker_process_init_handler_never_raises(monkeypatch):
    from cvenom import tasks

    def boom():
        raise RuntimeError("no db")

    monkeypatch.setattr(tasks, "get_engine", boom)
    tasks.reset_db_engine_after_fork()


def test_alerts_dispatch_and_purge_sessions_scheduled():
    from celery.schedules import crontab
    from cvenom.tasks import alerts_dispatch_task, beat_schedule, celery_app, purge_sessions_task
    assert beat_schedule["alerts-dispatch"] == {"task": alerts_dispatch_task.name, "schedule": 60.0,
                                                "options": {"expires": 55}}
    assert beat_schedule["maintenance-purge-sessions"]["schedule"] == crontab(minute=41, hour=3)
    assert beat_schedule["maintenance-purge-sessions"]["task"] == purge_sessions_task.name
    assert alerts_dispatch_task.name in celery_app.tasks and purge_sessions_task.name in celery_app.tasks


def test_alerts_dispatch_job_runs_with_lock(db_session, factory):
    import cvenom.tasks as tasks
    lock = FakeLock()
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    out = tasks.alerts_dispatch_job(lock=lock, session_factory=factory, sinks={}, now=now)
    assert out["ok"] is True and out["events"] == 0
    assert lock.acquired == [("alerts-dispatch", 120)]
    assert lock.released == ["alerts-dispatch"]


def test_alerts_dispatch_job_lock_held(factory):
    import cvenom.tasks as tasks
    lock = FakeLock(held=True)
    assert tasks.alerts_dispatch_job(lock=lock, session_factory=factory) == {"skipped": True}
    assert lock.released == []


def test_alerts_dispatch_job_never_raises():
    import cvenom.tasks as tasks

    @contextmanager
    def bad():
        raise RuntimeError("db down")
        yield

    lock = FakeLock()
    assert tasks.alerts_dispatch_job(lock=lock, session_factory=bad, sinks={}) == {"ok": False}
    assert lock.released == ["alerts-dispatch"]


def test_alerts_dispatch_job_defaults_to_build_sinks(factory, monkeypatch):
    import cvenom.tasks as tasks
    called = []
    monkeypatch.setattr(tasks, "build_sinks", lambda: called.append(1) or {})
    tasks.alerts_dispatch_job(lock=FakeLock(), session_factory=factory)
    assert called == [1]


def test_purge_sessions_job_deletes_old_expired_and_revoked(db_session, factory):
    import uuid
    import cvenom.tasks as tasks
    from sqlalchemy import select
    from cvenom.models import User, UserSession, UserSessionUsedRefresh
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    u = User(email="p@x.io", password_hash="h", role="member")
    db_session.add(u)
    db_session.flush()

    def mk(name, expires, revoked=None):
        s = UserSession(id=uuid.uuid4(), user_id=u.id, refresh_hash=name * 64, expires_at=expires,
                        revoked_at=revoked)
        db_session.add(s)
        return s

    old = now - timedelta(days=8)
    recent = now - timedelta(days=2)
    future = now + timedelta(days=5)
    s_old_exp = mk("a", old)
    mk("b", future, revoked=old)          # old revoked
    mk("c", recent)                       # recently expired: kept
    mk("d", future, revoked=recent)       # recently revoked: kept
    mk("e", future)                       # live: kept
    db_session.flush()
    db_session.add(UserSessionUsedRefresh(hash="z" * 64, session_id=s_old_exp.id))
    db_session.flush()
    lock = FakeLock()
    out = tasks.purge_sessions_job(lock=lock, session_factory=factory, now=now)
    assert out == {"ok": True, "sessions": 2, "invites": 0, "signing_keys": 0,
                   "alert_deliveries": 0, "alert_events": 0}
    db_session.expire_all()
    assert {s.refresh_hash[0] for s in db_session.scalars(select(UserSession))} == {"c", "d", "e"}
    assert db_session.scalars(select(UserSessionUsedRefresh)).all() == []
    assert lock.acquired == [("maintenance-purge-sessions", 3600)]
    assert lock.released == ["maintenance-purge-sessions"]


def test_purge_sessions_job_lock_held(factory):
    import cvenom.tasks as tasks
    assert tasks.purge_sessions_job(lock=FakeLock(held=True), session_factory=factory) == {"skipped": True}


def test_purge_sessions_job_release_failure_swallowed(factory):
    import cvenom.tasks as tasks

    class BadRelease(FakeLock):
        def release(self, name):
            raise RuntimeError("redis down")

    out = tasks.purge_sessions_job(lock=BadRelease(), session_factory=factory,
                                   now=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert out["ok"] is True


def test_alerts_dispatch_job_failure_logs_type_and_frames_not_message(caplog):
    import cvenom.tasks as tasks

    @contextmanager
    def bad():
        raise RuntimeError("topsecret-message")
        yield

    with caplog.at_level("ERROR", logger="cvenom.tasks"):
        # evaluate-stage errors are absorbed; force a hard failure via sinks lookup
        out = tasks.alerts_dispatch_job(lock=FakeLock(), session_factory=bad,
                                        sinks=None, now=datetime(2026, 6, 1))  # naive now -> ValueError
    assert out == {"ok": False}
    assert "ValueError" in caplog.text and "File" in caplog.text


def test_run_collector_publishes_after_commit(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    fake_registry(make_fake())
    seen = []

    def pub(what):
        # runs after the session block exited: the row is already written
        seen.append((what, db_session.get(Cve, "CVE-2099-0001") is not None))

    out = run_collector("fake_t", session_factory=factory, lock=FakeLock(), publisher=pub)
    assert out["published"] is True and seen == [(["lanes"], True)]


def test_run_collector_publish_failure_does_not_fail_run(db_session, factory, fake_registry, caplog):
    from cvenom.tasks import run_collector
    fake_registry(make_fake())

    def pub(what):
        raise ConnectionError("redis://user:secret@host")

    out = run_collector("fake_t", session_factory=factory, lock=FakeLock(), publisher=pub)
    assert out["ok"] is True and out["published"] is False and out["cves"] == 1
    assert "secret" not in caplog.text and "ConnectionError" in caplog.text


def test_run_collector_no_publish_on_failure_or_skip(db_session, factory, fake_registry):
    from cvenom.tasks import run_collector
    fake_registry(make_fake(fail=True))
    calls = []
    out = run_collector("fake_t", session_factory=factory, lock=FakeLock(), publisher=calls.append)
    assert out["ok"] is False and out["published"] is False and calls == []


def test_default_publisher_reaches_channel(db_session, factory, fake_registry, monkeypatch):
    import json

    import fakeredis

    import cvenom.tasks as tasks
    from cvenom import live

    monkeypatch.undo()  # drop the autouse no-op so the real _publish_live runs
    r = fakeredis.FakeRedis()
    monkeypatch.setattr(tasks, "_default_redis_client", lambda: r)
    sub = r.pubsub()
    sub.subscribe(live.CHANNEL)
    sub.get_message(timeout=1)
    fake_registry(make_fake())
    out = tasks.run_collector("fake_t", session_factory=factory, lock=FakeLock())
    assert out["published"] is True
    msg = sub.get_message(timeout=1)
    assert json.loads(msg["data"])["what"] == ["lanes"]


def test_worker_ready_checks_secrets_key_and_only_logs(monkeypatch, caplog):
    import cvenom.tasks as tasks
    from cvenom.config import get_settings

    monkeypatch.setattr(tasks.refresh_geoip_task, "delay", lambda: None)
    monkeypatch.delenv("SECRETS_KEY", raising=False)
    get_settings.cache_clear()
    try:
        with caplog.at_level("ERROR", logger="cvenom.tasks"):
            from celery.signals import worker_ready

            worker_ready.send(sender=None)  # must not raise
    finally:
        get_settings.cache_clear()
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert any("SECRETS_KEY" in m and "SecretsKeyMissing" in m for m in errors)


# ------------------------------------------------------- M-j: retention


PURGE_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _purge(factory):
    import cvenom.tasks as tasks

    return tasks.purge_sessions_job(lock=FakeLock(), session_factory=factory, now=PURGE_NOW)


def test_purge_invites(db_session, factory):
    from sqlalchemy import select
    from cvenom.models import Invite

    def mk(tag, expires, used=None):
        db_session.add(Invite(email=f"{tag}@x.io", role="member", token_hash=tag * 64,
                              expires_at=expires, used_at=used))

    d = lambda n: PURGE_NOW - timedelta(days=n)  # noqa: E731
    mk("a", d(8))                                  # expired > 7d: deleted
    mk("b", d(6))                                  # expired < 7d: kept
    mk("c", PURGE_NOW + timedelta(days=1))         # live: kept
    mk("d", PURGE_NOW + timedelta(days=1), d(31))  # used > 30d: deleted
    mk("e", PURGE_NOW + timedelta(days=1), d(29))  # used < 30d: kept
    db_session.flush()
    out = _purge(factory)
    assert out["invites"] == 2
    db_session.expire_all()
    assert {i.email[0] for i in db_session.scalars(select(Invite))} == {"b", "c", "e"}


def test_purge_signing_keys_past_grace(db_session, factory):
    from sqlalchemy import select
    from cvenom.config import get_settings
    from cvenom.models import SigningKey

    grace = timedelta(minutes=get_settings().access_ttl_minutes) + timedelta(hours=1)
    cutoff = PURGE_NOW - grace - timedelta(days=1)

    def mk(kid, retired):
        db_session.add(SigningKey(kid=kid, private_enc="v1:x", public_pem="p",
                                  created_at=PURGE_NOW - timedelta(days=30), retired_at=retired))

    mk("old", cutoff - timedelta(minutes=1))     # deleted
    mk("recent", cutoff + timedelta(minutes=1))  # kept (still near its grace window)
    mk("active", None)                           # never deleted
    db_session.flush()
    out = _purge(factory)
    assert out["signing_keys"] == 1
    db_session.expire_all()
    assert {k.kid for k in db_session.scalars(select(SigningKey))} == {"recent", "active"}


def _alert_fixture(db_session):
    from cvenom.models import AlertRecipient, AlertRule

    rule = AlertRule(name="r", kind="kev_added")
    db_session.add(rule)
    db_session.flush()
    rec = AlertRecipient(rule_id=rule.id, channel="email", email="a@x.io")
    db_session.add(rec)
    db_session.flush()
    return rule, rec


def test_purge_alert_events(db_session, factory):
    from sqlalchemy import select
    from cvenom.models import AlertDelivery, AlertEvent

    rule, rec = _alert_fixture(db_session)
    d = lambda n: PURGE_NOW - timedelta(days=n)  # noqa: E731

    def ev(tag, processed):
        e = AlertEvent(type="kev_added", cve_id=f"CVE-2099-{tag}", source=tag, processed_at=processed)
        db_session.add(e)
        db_session.flush()
        return e

    ev("0001", d(31))                       # old, no deliveries: deleted
    ev("0002", d(29))                       # recent: kept
    ev("0003", None)                        # unprocessed: kept
    pend = ev("0004", d(31))                # old but a pending delivery: kept
    sent = ev("0005", d(31))                # old, a recent sent delivery: kept (FK cascades)
    db_session.add_all([
        AlertDelivery(event_id=pend.id, rule_id=rule.id, recipient_id=rec.id, cve_id="CVE-2099-0004",
                      status="pending", created_at=d(31)),
        AlertDelivery(event_id=sent.id, rule_id=rule.id, recipient_id=rec.id, cve_id="CVE-2099-0005",
                      status="sent", created_at=d(31)),
    ])
    db_session.flush()
    out = _purge(factory)
    assert out["alert_events"] == 1
    db_session.expire_all()
    assert {e.source for e in db_session.scalars(select(AlertEvent))} == {"0002", "0003", "0004", "0005"}
    assert len(db_session.scalars(select(AlertDelivery)).all()) == 2


def test_purge_alert_deliveries(db_session, factory):
    from sqlalchemy import select
    from cvenom.models import AlertDelivery, AlertEvent

    rule, rec = _alert_fixture(db_session)
    d = lambda n: PURGE_NOW - timedelta(days=n)  # noqa: E731
    e = AlertEvent(type="kev_added", cve_id="CVE-2099-0001", source="s", processed_at=d(1))
    db_session.add(e)
    db_session.flush()
    rows = {
        "sent-old": ("sent", d(91)),        # deleted
        "failed-old": ("failed", d(91)),    # deleted
        "pending-old": ("pending", d(91)),  # kept: never purge pending
        "sent-new": ("sent", d(89)),        # kept
    }
    for i, (tag, (status, created)) in enumerate(rows.items()):
        db_session.add(AlertDelivery(event_id=e.id, rule_id=rule.id, recipient_id=rec.id,
                                     cve_id=f"CVE-2099-{i:04d}", status=status, created_at=created,
                                     last_error=tag))
    db_session.flush()
    out = _purge(factory)
    assert out["alert_deliveries"] == 2
    db_session.expire_all()
    assert {x.last_error for x in db_session.scalars(select(AlertDelivery))} == {"pending-old", "sent-new"}
    assert db_session.get(AlertEvent, e.id) is not None


def test_alerts_dispatch_messages_expire():
    # M-f: a backlog of 60 s dispatch messages (worker down) must not pile up.
    from cvenom.tasks import beat_schedule

    assert beat_schedule["alerts-dispatch"]["options"] == {"expires": 55}
