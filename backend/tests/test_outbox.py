from contextlib import contextmanager
from datetime import date, datetime, timezone

import pytest
from sqlalchemy import select

import cvenom.tasks as tasks
from cvenom.collectors.base import REGISTRY, Collector, CollectorResult
from cvenom.models import AlertEvent, CollectorRun, Cve
from cvenom.pipeline import persist_events
from cvenom.schemas import NormalizedCve


class FakeLock:
    def acquire(self, name, ttl):
        return True

    def release(self, name):
        pass


@pytest.fixture
def fake_registry():
    added = []

    def add(cls):
        REGISTRY[cls.name] = cls
        added.append(cls.name)
        return cls

    yield add
    for n in added:
        REGISTRY.pop(n, None)


@pytest.fixture
def txn_factory(db_session):
    """Mimics session_scope: commit (release savepoint) on success, rollback on error."""
    @contextmanager
    def f():
        with db_session.begin_nested():
            yield db_session
    return f


def make_events_fake(events, name="fake_ob"):
    class Fake(Collector):
        cadence_seconds = 100

        async def fetch(self):
            return {}

        def normalize(self, raw):
            self.state["cursor"] = "new"
            return CollectorResult(
                cves=[NormalizedCve(cve_id="CVE-2099-0001", cvss=9.8)],
                events=list(events),
            )

    Fake.name = name
    return Fake


def _rows(db_session):
    return list(db_session.scalars(select(AlertEvent).order_by(AlertEvent.id)))


def _run(txn_factory):
    return tasks.run_collector("fake_ob", session_factory=txn_factory, lock=FakeLock())


def test_success_commits_events_with_state(db_session, txn_factory, fake_registry):
    fake_registry(make_events_fake([
        {"type": "kev_added", "cve_id": "CVE-2099-0001", "source": "cisa", "extra": 1},
        {"type": "other", "cve_id": "CVE-2099-0002"},
    ]))
    out = _run(txn_factory)
    assert out["ok"] and out["events_persisted"] == 2 and len(out["events"]) == 2
    rows = _rows(db_session)
    assert [(r.type, r.cve_id, r.source, r.payload) for r in rows] == [
        ("kev_added", "CVE-2099-0001", "cisa", {"extra": 1}),
        ("other", "CVE-2099-0002", "fake_ob", {}),
    ]
    assert all(r.processed_at is None for r in rows)
    assert db_session.get(CollectorRun, "fake_ob").state == {"cursor": "new"}


def test_ingest_raises_commits_nothing(db_session, txn_factory, fake_registry, monkeypatch):
    fake_registry(make_events_fake([{"type": "x"}]))
    prior = datetime(2020, 1, 1, tzinfo=timezone.utc)
    db_session.add(CollectorRun(collector="fake_ob", last_run=prior, state={"k": 1}))
    db_session.flush()

    def boom(*a, **k):
        raise RuntimeError("ingest boom")

    monkeypatch.setattr(tasks, "ingest", boom)
    with pytest.raises(RuntimeError, match="ingest boom"):
        _run(txn_factory)
    assert _rows(db_session) == []
    row = db_session.get(CollectorRun, "fake_ob")
    assert row.last_run == prior and row.state == {"k": 1}


def test_failure_after_persist_before_commit_rolls_back(db_session, txn_factory, fake_registry,
                                                        monkeypatch):
    fake_registry(make_events_fake([{"type": "x", "cve_id": "CVE-2099-0001"}]))
    prior = datetime(2020, 1, 1, tzinfo=timezone.utc)
    db_session.add(CollectorRun(collector="fake_ob", last_run=prior, state={"k": 1}))
    db_session.flush()
    persisted = []
    real = tasks.persist_events

    def spy(*a, **k):
        n = real(*a, **k)
        persisted.append(n)
        return n

    monkeypatch.setattr(tasks, "persist_events", spy)

    @contextmanager
    def failing_commit():
        with db_session.begin_nested():
            yield db_session
            raise RuntimeError("commit failed")

    with pytest.raises(RuntimeError, match="commit failed"):
        tasks.run_collector("fake_ob", session_factory=failing_commit, lock=FakeLock())
    assert persisted == [1]  # persisted, then rolled back
    assert _rows(db_session) == []
    row = db_session.get(CollectorRun, "fake_ob")
    assert row.last_run == prior and row.state == {"k": 1}
    assert db_session.get(Cve, "CVE-2099-0001") is None


def test_rerun_without_new_events_adds_no_rows(db_session, txn_factory, fake_registry):
    cls = make_events_fake([{"type": "kev_added", "cve_id": "CVE-2099-0001"}])
    fake_registry(cls)
    assert _run(txn_factory)["events_persisted"] == 1
    # Second run: the source now yields no events.
    REGISTRY["fake_ob"] = make_events_fake([])
    out = _run(txn_factory)
    assert out["ok"] and out["events_persisted"] == 0
    assert len(_rows(db_session)) == 1


def test_collector_error_writes_no_events(db_session, txn_factory, fake_registry):
    cls = make_events_fake([{"type": "x"}])

    async def fetch(self):
        raise RuntimeError("net")

    cls.fetch = fetch
    fake_registry(cls)
    out = _run(txn_factory)
    assert out["ok"] is False and out["events_persisted"] == 0
    assert _rows(db_session) == []
    assert db_session.get(CollectorRun, "fake_ob") is None


def test_dedupe_within_run(db_session):
    n = persist_events(db_session, [
        {"type": "a", "cve_id": "CVE-2099-0001", "n": 1},
        {"type": "a", "cve_id": "CVE-2099-0001", "n": 2},
        {"type": "a", "cve_id": "CVE-2099-0002"},
        {"type": "b", "cve_id": "CVE-2099-0001"},
    ], source_default="s")
    assert n == 3
    rows = _rows(db_session)
    assert len(rows) == 3
    assert rows[0].payload == {"n": 1}


def test_invalid_events_skipped_with_warning(db_session, caplog):
    bad = [
        {"cve_id": "CVE-2099-0001"},
        {"type": ""},
        {"type": 5},
        {"type": "t" * 65},
        {"type": "ok", "cve_id": "not-a-cve"},
        {"type": "ok", "cve_id": 123},
        {"type": "ok", "source": "s" * 65},
        "nonsense",
    ]
    good = {"type": "ok", "cve_id": "CVE-2099-0003"}
    with caplog.at_level("WARNING", logger="cvenom.pipeline"):
        n = persist_events(db_session, bad + [good], source_default="s")
    assert n == 1
    assert [r.cve_id for r in _rows(db_session)] == ["CVE-2099-0003"]
    assert caplog.text.count("skipping invalid alert event") == len(bad)


def test_payload_json_safe(db_session):
    persist_events(db_session, [{
        "type": "t",
        "when": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "day": date(2026, 1, 2),
        "nested": {"d": date(2026, 1, 3), "l": [datetime(2026, 1, 4)]},
        "nul": "a\x00b",
        "nan": float("nan"),
    }], source_default="s")
    db_session.expire_all()
    p = _rows(db_session)[0].payload
    assert p["when"] == "2026-01-02T03:04:05+00:00"
    assert p["day"] == "2026-01-02"
    assert p["nested"] == {"d": "2026-01-03", "l": ["2026-01-04T00:00:00"]}
    assert p["nul"] == "ab"
    assert p["nan"] is None
