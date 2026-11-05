"""Celery app, collector tasks, and beat schedule."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

import httpx
from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init, worker_ready
from sqlalchemy import func, select

from cvenom.collectors import abusech, cfradar, dshield, epss, kev, news, nvd, osv, ransomware, vulncheck  # noqa: F401  (register)
from cvenom.collectors.base import REGISTRY
from cvenom.config import get_settings
from cvenom.db import get_engine, session_scope
from cvenom.models import CollectorRun, Cve
from cvenom.geoip import ASN_FILE, COUNTRY_FILE, refresh_geoip
from cvenom.pipeline import ingest, persist_events, purge_old_geo_events

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
    summary = {"collector": name, "ok": False, "cves": 0, "stories": 0, "events": [], "events_persisted": 0, "skipped": False}
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
            # Outbox: same transaction as the data and the seen-state.
            persisted = persist_events(session, events, source_default=name)
            row.last_run = started_at
            row.state = collector.state
        summary.update(ok=True, cves=len(result.cves), stories=len(result.stories), events=events,
                       events_persisted=persisted)
        return summary
    finally:
        lock.release(name)


@celery_app.task(name="cvenom.tasks.run_collector_task")
def run_collector_task(name: str) -> dict:
    return run_collector(name)


GEOIP_LOCK = "maintenance-geoip"
PURGE_GEO_LOCK = "maintenance-purge-geo"
MAINTENANCE_LOCK_TTL = 3600


GEOIP_MAX_AGE = timedelta(days=7)


def _geoip_fresh(directory) -> bool:
    """True when every expected GeoIP DB file exists and is younger than GEOIP_MAX_AGE."""
    cutoff = time.time() - GEOIP_MAX_AGE.total_seconds()
    for name in (COUNTRY_FILE, ASN_FILE):
        try:
            if (Path(directory) / name).stat().st_mtime < cutoff:
                return False
        except OSError:
            return False
    return True


def refresh_geoip_job(*, lock: CollectorLock | None = None, force: bool = False) -> dict:
    lock = lock if lock is not None else RedisLock()
    if not lock.acquire(GEOIP_LOCK, MAINTENANCE_LOCK_TTL):
        log.info("geoip refresh already running; skipping")
        return {"skipped": True}
    try:
        settings = get_settings()
        if not force and _geoip_fresh(settings.geoip_dir):
            return {"ok": True, "skipped": "fresh"}
        provider = asyncio.run(refresh_geoip(settings.geoip_dir, settings))
        return {"ok": True, "provider": provider}
    except Exception as exc:
        # No message/traceback: httpx errors embed the (presigned) download URL.
        if isinstance(exc, httpx.HTTPStatusError):
            log.warning("geoip refresh failed: %s (HTTP %s)", type(exc).__name__,
                        exc.response.status_code)
        else:
            log.warning("geoip refresh failed: %s", type(exc).__name__)
        return {"ok": False}
    finally:
        lock.release(GEOIP_LOCK)


def purge_geo_job(*, session_factory=session_scope, lock: CollectorLock | None = None,
                  now: datetime | None = None) -> dict:
    lock = lock if lock is not None else RedisLock()
    if not lock.acquire(PURGE_GEO_LOCK, MAINTENANCE_LOCK_TTL):
        log.info("geo purge already running; skipping")
        return {"skipped": True}
    try:
        now = now if now is not None else datetime.now(timezone.utc)
        with session_factory() as session:
            deleted = purge_old_geo_events(session, now, days=get_settings().geo_retention_days)
        return {"ok": True, "deleted": deleted}
    finally:
        lock.release(PURGE_GEO_LOCK)


@celery_app.task(name="cvenom.tasks.refresh_geoip_task")
def refresh_geoip_task() -> dict:
    return refresh_geoip_job()


@worker_ready.connect
def bootstrap_geoip(*args: Any, **kwargs: Any) -> None:
    """Fetch GeoIP databases at worker start; the freshness check keeps repeats cheap."""
    try:
        refresh_geoip_task.delay()
    except Exception as exc:
        log.warning("geoip bootstrap enqueue failed: %s", type(exc).__name__)


@worker_process_init.connect
def reset_db_engine_after_fork(*args: Any, **kwargs: Any) -> None:
    """Drop pooled connections inherited from the parent so forked children never share sockets."""
    try:
        get_engine().dispose(close=False)
    except Exception as exc:
        log.warning("db engine reset after fork failed: %s", type(exc).__name__)


@celery_app.task(name="cvenom.tasks.purge_geo_task")
def purge_geo_task() -> dict:
    return purge_geo_job()


beat_schedule = {
    f"collect-{n}": {
        "task": run_collector_task.name,
        "schedule": cls.cadence_seconds,
        "args": (n,),
    }
    for n, cls in REGISTRY.items()
}
beat_schedule["maintenance-geoip"] = {"task": refresh_geoip_task.name, "schedule": crontab(minute=17, hour="*/6")}
beat_schedule["maintenance-purge-geo"] = {"task": purge_geo_task.name, "schedule": crontab(minute=23)}
celery_app.conf.beat_schedule = beat_schedule
