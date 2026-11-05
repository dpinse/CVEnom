"""Collector framework and resilient HTTP helper."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from cvenom.schemas import NormalizedCve, NormalizedStory

log = logging.getLogger(__name__)

USER_AGENT = "CVEnom/0.1 (+threat-radar)"
BACKOFF_BASE = 0.5
MAX_RETRY_AFTER = 30.0

# Patchable in tests so backoff does not slow them down.
_sleep = asyncio.sleep


@dataclass
class CollectorResult:
    cves: list[NormalizedCve] = field(default_factory=list)
    stories: list[NormalizedStory] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)


class Collector(ABC):
    name: str
    cadence_seconds: int

    @abstractmethod
    async def fetch(self) -> Any: ...

    @abstractmethod
    def normalize(self, raw: Any) -> CollectorResult: ...

    async def run(self) -> CollectorResult:
        try:
            raw = await self.fetch()
            return self.normalize(raw)
        except Exception:
            log.exception("collector %s failed", self.name)
            return CollectorResult()


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return min(max(float(value), 0.0), MAX_RETRY_AFTER)
    except ValueError:
        return None


async def http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    retries: int = 3,
    timeout: float = 20,
) -> Any:
    """GET url and return parsed JSON, retrying 429/5xx/transport errors."""
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    attempts = max(retries, 1)
    async with httpx.AsyncClient(timeout=timeout, headers=hdrs) as client:
        for attempt in range(attempts):
            last = attempt == attempts - 1
            delay = BACKOFF_BASE * (2**attempt)
            try:
                resp = await client.get(url, params=params)
            except (httpx.TimeoutException, httpx.TransportError):
                if last:
                    raise
                await _sleep(delay)
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                if last:
                    resp.raise_for_status()
                wait = _retry_after(resp) if resp.status_code == 429 else None
                await _sleep(delay if wait is None else wait)
                continue
            resp.raise_for_status()
            return resp.json()
    raise RuntimeError("unreachable")  # pragma: no cover


REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    if cls.name in REGISTRY:
        raise ValueError(f"duplicate collector name: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls
