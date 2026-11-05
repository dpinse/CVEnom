from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from cvenom.collectors.base import REGISTRY, Collector, CollectorResult
from cvenom.models import Cve, CollectorRun
from cvenom.schemas import NormalizedCve


def test_registry_contains_all_core_collectors():
    import cvenom.tasks  # triggers collector imports/registration
    from cvenom.collectors.base import REGISTRY
    assert {"nvd","epss","cisa_kev","vulncheck_kev","osv"} <= set(REGISTRY)


def test_beat_schedule_has_entry_per_collector():
    from cvenom.tasks import beat_schedule
    from cvenom.collectors.base import REGISTRY
    assert len(beat_schedule) == len(REGISTRY)


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

    def bad_ingest(session, result, *, enrich_only=False):
        from cvenom.pipeline import ingest
        ingest(session, result, enrich_only=enrich_only)  # writes CVE rows first
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

    def bad_ingest(session, result, *, enrich_only=False):
        raise RuntimeError("ingest boom")

    monkeypatch.setattr(tasks, "ingest", bad_ingest)
    with pytest.raises(RuntimeError):
        tasks.run_collector("fake_t", session_factory=tx, lock=FakeLock())
    assert db_session.get(CollectorRun, "fake_t") is None
