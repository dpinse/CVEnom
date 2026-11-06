"""Collector framework and resilient HTTP helper."""

from __future__ import annotations

import asyncio
import copy
import logging
import math
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import httpx

from cvenom.schemas import NormalizedCve, NormalizedGeoEvent, NormalizedStory

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
    geo_events: list[NormalizedGeoEvent] = field(default_factory=list)


class Collector(ABC):
    name: str
    cadence_seconds: int

    def __init__(self, since: datetime | None = None, state: dict | None = None) -> None:
        self.since = since
        self.state = copy.deepcopy(state or {})
        self.last_error: Exception | None = None

    @abstractmethod
    async def fetch(self) -> Any: ...

    @abstractmethod
    def normalize(self, raw: Any) -> CollectorResult: ...

    async def run(self) -> CollectorResult:
        self.last_error = None
        try:
            raw = await self.fetch()
            return self.normalize(raw)
        except Exception as exc:
            self.last_error = exc
            log.exception("collector %s failed", self.name)
            return CollectorResult()


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    if not math.isfinite(seconds):  # "nan"/"inf" parse as floats: use normal backoff
        return None
    return min(max(seconds, 0.0), MAX_RETRY_AFTER)


class ResponseTooLarge(Exception):
    """Response body exceeded the caller's max_bytes cap (deterministic; never retried)."""


async def _read_capped(resp: httpx.Response, max_bytes: int) -> bytes:
    declared = resp.headers.get("Content-Length")
    if declared is not None and declared.isdigit() and int(declared) > max_bytes:
        raise ResponseTooLarge(f"declared {declared} bytes exceeds cap {max_bytes}")
    buf = bytearray()
    async for chunk in resp.aiter_bytes():
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise ResponseTooLarge(f"response exceeds cap of {max_bytes} bytes")
    return bytes(buf)


async def _request(
    url: str,
    *,
    headers: dict[str, str] | None,
    params: dict[str, Any] | None,
    retries: int,
    timeout: float,
    max_bytes: int,
    accept_304: bool = False,
    follow_redirects: bool = False,
    method: str = "GET",
    json_body: Any = None,
) -> httpx.Response:
    """GET (or POST with json_body) url (streamed, size-capped), retrying 429/5xx/transport errors.

    Returns an OK response whose body is fully loaded. ResponseTooLarge is raised
    as soon as the cap is exceeded and is never retried.
    """
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    attempts = max(retries, 1)
    async with httpx.AsyncClient(
        timeout=timeout, headers=hdrs, follow_redirects=follow_redirects
    ) as client:
        for attempt in range(attempts):
            last = attempt == attempts - 1
            delay = BACKOFF_BASE * (2**attempt)
            try:
                async with client.stream(method, url, params=params, json=json_body) as resp:
                    status = resp.status_code
                    if status == 429 or status >= 500:
                        if last:
                            resp.raise_for_status()
                        wait = _retry_after(resp) if status == 429 else None
                        retry_delay = delay if wait is None else wait
                    elif accept_304 and status == 304:
                        return httpx.Response(304, headers=resp.headers, request=resp.request)
                    else:
                        resp.raise_for_status()
                        body = await _read_capped(resp, max_bytes)
                        # body is already decoded: drop encoding/length headers so httpx
                        # treats it as identity content (Content-Type charset is kept).
                        clean = httpx.Headers(
                            [
                                (k, v)
                                for k, v in resp.headers.multi_items()
                                if k.lower()
                                not in ("content-encoding", "content-length", "transfer-encoding")
                            ]
                        )
                        return httpx.Response(
                            status, headers=clean, content=body, request=resp.request
                        )
            except (httpx.TimeoutException, httpx.TransportError):
                if last:
                    raise
                await _sleep(delay)
                continue
            await _sleep(retry_delay)
    raise RuntimeError("unreachable")  # pragma: no cover


async def http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    retries: int = 3,
    timeout: float = 20,
    max_bytes: int = 25_000_000,
) -> Any:
    """GET url and return parsed JSON, retrying 429/5xx/transport errors."""
    resp = await _request(
        url, headers=headers, params=params, retries=retries, timeout=timeout, max_bytes=max_bytes
    )
    return resp.json()


async def http_post_json(
    url: str,
    *,
    json_body: Any,
    headers: dict[str, str] | None = None,
    retries: int = 3,
    timeout: float = 20,
    max_bytes: int = 25_000_000,
) -> Any:
    """POST json_body to url and return parsed JSON, retrying 429/5xx/transport errors."""
    resp = await _request(
        url,
        headers=headers,
        params=None,
        retries=retries,
        timeout=timeout,
        max_bytes=max_bytes,
        method="POST",
        json_body=json_body,
    )
    return resp.json()


async def http_get_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    retries: int = 3,
    timeout: float = 20,
    max_bytes: int = 25_000_000,
) -> str:
    """GET url and return the body text, retrying 429/5xx/transport errors."""
    resp = await _request(
        url, headers=headers, params=params, retries=retries, timeout=timeout, max_bytes=max_bytes
    )
    return resp.text


async def http_stream_lines(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    retries: int = 3,
    timeout: float = 20,
    max_bytes: int = 25_000_000,
) -> AsyncIterator[str]:
    """GET url and yield its body line by line without buffering the whole body.

    Same client settings as _request (no redirects, same user agent/timeout) and the
    same 429/5xx/transport retry, which applies only until the first body chunk is read
    (after that a transport error propagates; the stream is never re-issued).
    The body is never fully held: once more than max_bytes have been read, the
    lines read so far have been yielded and ResponseTooLarge is raised. Callers
    may stop early (use contextlib.aclosing) to avoid reading the rest.
    """
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    attempts = max(retries, 1)
    started = False
    async with httpx.AsyncClient(timeout=timeout, headers=hdrs, follow_redirects=False) as client:
        for attempt in range(attempts):
            last = attempt == attempts - 1
            delay = BACKOFF_BASE * (2**attempt)
            try:
                async with client.stream("GET", url, params=params) as resp:
                    status = resp.status_code
                    if status == 429 or status >= 500:
                        if last:
                            resp.raise_for_status()
                        wait = _retry_after(resp) if status == 429 else None
                        retry_delay = delay if wait is None else wait
                    else:
                        resp.raise_for_status()
                        total = 0
                        parts: list[bytes] = []  # carried partial line, joined lazily
                        async for chunk in resp.aiter_bytes():
                            started = True
                            total += len(chunk)
                            *lines, tail = chunk.split(b"\n")
                            if lines:
                                parts.append(lines[0])
                                lines[0] = b"".join(parts)
                                parts = []
                                for raw in lines:
                                    yield raw.decode("utf-8", "replace").rstrip("\r")
                            if tail:
                                parts.append(tail)
                            if total > max_bytes:
                                raise ResponseTooLarge(f"stream exceeds budget of {max_bytes} bytes")
                        if parts:
                            yield b"".join(parts).decode("utf-8", "replace").rstrip("\r")
                        return
            except (httpx.TimeoutException, httpx.TransportError):
                if last or started:  # never re-issue once body bytes were read
                    raise
                await _sleep(delay)
                continue
            await _sleep(retry_delay)
    raise RuntimeError("unreachable")  # pragma: no cover


async def http_get_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    retries: int = 3,
    timeout: float = 60,
    max_bytes: int = 200_000_000,
    follow_redirects: bool = False,
) -> bytes:
    """GET url and return the raw body bytes (size-capped)."""
    resp = await _request(
        url, headers=headers, params=params, retries=retries,
        timeout=timeout,
        max_bytes=max_bytes,
        follow_redirects=follow_redirects,
    )
    return resp.content


async def http_get_conditional(
    url: str,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
    headers: dict[str, str] | None = None,
    max_bytes: int = 25_000_000,
) -> tuple[int, bytes, dict[str, str]]:
    """Conditional GET. Returns (status, body, lower-cased headers); 304 has an empty body."""
    hdrs = dict(headers or {})
    if etag:
        hdrs["If-None-Match"] = etag
    if last_modified:
        hdrs["If-Modified-Since"] = last_modified
    resp = await _request(
        url,
        headers=hdrs,
        params=None,
        retries=3,
        timeout=20,
        max_bytes=max_bytes,
        accept_304=True,
    )
    out = {k.lower(): v for k, v in resp.headers.items()}
    return resp.status_code, (b"" if resp.status_code == 304 else resp.content), out


REGISTRY: dict[str, type[Collector]] = {}


def str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def parse_iso_date(value: object) -> date | None:
    """Leading YYYY-MM-DD of a string; anything else (or unparseable) gives None."""
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def ransomware_flag(value: object) -> bool | None:
    """KEV knownRansomwareCampaignUse: Known -> True, Unknown -> False, else None."""
    if value == "Known":
        return True
    if value == "Unknown":
        return False
    return None


def register(cls: type[Collector]) -> type[Collector]:
    if cls.name in REGISTRY:
        raise ValueError(f"duplicate collector name: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls
