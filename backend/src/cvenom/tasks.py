"""Celery app, collector tasks, and beat schedule."""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from celery import Celery
from sqlalchemy import func, select

from cvenom.collectors import dshield, epss, kev, news, nvd, osv, ransomware, vulncheck  # noqa: F401  (register)
from cvenom.collectors.base import REGISTRY
from cvenom.config import get_settings
from cvenom.db import session_scope
from cvenom.models import CollectorRun, Cve
from cvenom.pipeline import ingest

log = logging.getLogger(__name__)

LOCK_PREFIX = "cvenom:lock:"
# Each incremental window starts this long before the previous run started, so a
# record published/modified late (or with source-side clock skew) is not missed.
# Upserts are idempotent, so the overlap is free.
WINDOW_OVERLAP = timedelta(hours=1)

celery_app = Celery("cvenom", broker=get_settings().redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


class CollectorLock(Protocol):
    def acquire(self, name: str, ttl: int) -> bool: ...

    def release(self, name: str) -> None: ...


_RELEASE_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


# One lazily-created client (one connection pool) shared by every default lock,
# so per-run RedisLock instances don't each open and leak a pool.
_redis_client: Any = None
_redis_client_guard = threading.Lock()


def _default_redis_client() -> Any:
    global _redis_client
    if _redis_client is None:
        with _redis_client_guard:
            if _redis_client is None:
                import redis

                _redis_client = redis.Redis.from_url(get_settings().redis_url)
    return _redis_client


class RedisLock:
    """Per-collector lock: SET NX EX; release deletes only if we still hold it."""

    def __init__(self, client: Any = None) -> None:
        self._client = client  # injectable (tests); None -> shared module client
        self._token = uuid.uuid4().hex

    @property
    def client(self) -> Any:
        return self._client if self._client is not None else _default_redis_client()

    def acquire(self, name: str, ttl: int) -> bool:
        return bool(self.client.set(LOCK_PREFIX + name, self._token, nx=True, ex=ttl))

    def release(self, name: str) -> None:
        # Atomic compare-and-delete: never delete another worker's lock.
        self.client.eval(_RELEASE_LUA, 1, LOCK_PREFIX + name, self._token)


def run_collector(name: str, *, session_factory=session_scope, lock: CollectorLock | None = None) -> dict:
    cls = REGISTRY[name]
    lock = lock if lock is not None else RedisLock()
    summary = {"collector": name, "ok": False, "cves": 0, "stories": 0, "events": [], "skipped": False}
    # The Redis lock is the cheap skip; the row lock (FOR UPDATE) below is the
    # correctness guarantee. TTL is 2x cadence so a slow run rarely outlives it.
    if not lock.acquire(name, 2 * cls.cadence_seconds):
        log.info("collector %s already running; skipping", name)
        summary["skipped"] = True
        return summary
    try:
        started_at = datetime.now(timezone.utc)
        # The DB session stays open during the network fetch by design
        # (single-transaction decision).
        with session_factory() as session:
            row = session.get(CollectorRun, name, with_for_update=True)
            if row is None:
                row = CollectorRun(collector=name, last_run=None, state={})
                session.add(row)
            since = row.last_run - WINDOW_OVERLAP if row.last_run is not None else None
            state = dict(row.state or {})
            enrich_only = getattr(cls, "enrich_only", False)
            if enrich_only:
                # Lets enrich-only collectors (EPSS) notice newly created CVE rows.
                state["cve_count"] = session.scalar(select(func.count()).select_from(Cve))
            collector = cls(since=since, state=state)
            result = asyncio.run(collector.run())
            if collector.last_error is not None:
                log.error("collector %s failed; window not advanced", name)
                if row in session.new:
                    session.expunge(row)
                return summary
            events = ingest(session, result, enrich_only=enrich_only)
            row.last_run = started_at
            row.state = collector.state
        summary.update(ok=True, cves=len(result.cves), stories=len(result.stories), events=events)
        return summary
    finally:
        lock.release(name)


@celery_app.task(name="cvenom.tasks.run_collector_task")
def run_collector_task(name: str) -> dict:
    return run_collector(name)


beat_schedule = {
    f"collect-{n}": {
        "task": run_collector_task.name,
        "schedule": cls.cadence_seconds,
        "args": (n,),
    }
    for n, cls in REGISTRY.items()
}
celery_app.conf.beat_schedule = beat_schedule
