"""Celery app, collector tasks, and beat schedule."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

from celery import Celery

from cvenom.collectors import epss, kev, nvd, osv, vulncheck  # noqa: F401  (register)
from cvenom.collectors.base import REGISTRY
from cvenom.config import get_settings
from cvenom.db import session_scope
from cvenom.models import CollectorRun
from cvenom.pipeline import ingest

log = logging.getLogger(__name__)

LOCK_PREFIX = "cvenom:lock:"

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


class RedisLock:
    """Per-collector lock: SET NX EX; release deletes only if we still hold it."""

    def __init__(self, client: Any = None) -> None:
        self._client = client
        self._token = uuid.uuid4().hex

    @property
    def client(self) -> Any:
        if self._client is None:
            import redis

            self._client = redis.Redis.from_url(get_settings().redis_url)
        return self._client

    def acquire(self, name: str, ttl: int) -> bool:
        return bool(self.client.set(LOCK_PREFIX + name, self._token, nx=True, ex=ttl))

    def release(self, name: str) -> None:
        key = LOCK_PREFIX + name
        held = self.client.get(key)
        if isinstance(held, bytes):
            held = held.decode()
        if held == self._token:
            self.client.delete(key)


def run_collector(name: str, *, session_factory=session_scope, lock: CollectorLock | None = None) -> dict:
    cls = REGISTRY[name]
    lock = lock if lock is not None else RedisLock()
    summary = {"collector": name, "ok": False, "cves": 0, "stories": 0, "events": [], "skipped": False}
    if not lock.acquire(name, cls.cadence_seconds):
        log.info("collector %s already running; skipping", name)
        summary["skipped"] = True
        return summary
    try:
        started_at = datetime.now(timezone.utc)
        with session_factory() as session:
            row = session.get(CollectorRun, name)
            if row is None:
                row = CollectorRun(collector=name, last_run=None, state={})
                session.add(row)
            collector = cls(since=row.last_run, state=row.state or {})
            result = asyncio.run(collector.run())
            if collector.last_error is not None:
                log.error("collector %s failed; window not advanced", name)
                if row.last_run is None and not row.state:
                    session.expunge(row)
                return summary
            events = ingest(session, result, enrich_only=getattr(cls, "enrich_only", False))
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
