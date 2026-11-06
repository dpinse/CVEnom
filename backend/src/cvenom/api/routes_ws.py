"""Live update WebSocket: /api/ws/live.

Auth is a first message (never a ?token= query: access logs record query
strings). Origin is checked before accept to stop cross-site hijacking.

Limits: a process-wide socket cap (in-process counter), and a per-IP cap kept
in Redis as a heartbeat ZSET (member per socket, score = last heartbeat), so
crashed workers cannot leak slots: stale members are pruned on connect.
One shared Redis subscriber per process fans out to per-socket bounded queues.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import time
import uuid
from datetime import UTC, datetime
from functools import partial
from urllib.parse import urlsplit

import anyio
from fastapi import APIRouter, WebSocket
from fastapi.concurrency import run_in_threadpool
from starlette.websockets import WebSocketDisconnect, WebSocketState

from cvenom.live import CHANNEL

from .deps import resolve_access
from .middleware import client_ip
from .ratelimit import get_redis, warn_rate_limited

log = logging.getLogger(__name__)
router = APIRouter()

WS_AUTH_TIMEOUT_S = 5.0
WS_PING_S = 30.0
WS_MAX_PER_IP = 5
WS_MAX_TOTAL = 200
WS_QUEUE_MAX = 16
WS_AUTH_MAX_BYTES = 4096
IP_KEY = "cvenom:ws:ip:"
PING = '{"type":"ping"}'
SUB_BACKOFF_MAX_S = 30.0
LIVE_WHAT = frozenset({"lanes", "geo", "stories"})

# KEYS[1]=bucket; ARGV: now, stale_before, max, ttl, member
_CONNECT_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
if redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[3]) then
  redis.call('ZADD', KEYS[1], ARGV[1], ARGV[5])
  redis.call('EXPIRE', KEYS[1], ARGV[4])
  return 1
end
return 0
"""


def _now() -> float:
    return time.time()


def _seconds_until(exp: int) -> float:
    return max(0.0, exp - time.time())


def _stale_after() -> float:
    return 2 * WS_PING_S + 5


def _bucket(ip: str) -> str:
    """IPv4: the address. IPv6: the /64 network, so one host cannot rotate
    through its address space to dodge the limit."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _relay_payload(data) -> str | None:
    """Re-serialize a pub/sub message to the fixed client shape, or None to drop
    it. Never forwards the raw string: only known `what` values reach clients."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    try:
        parsed = json.loads(data)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict) or parsed.get("type") != "updated":
        return None
    what = parsed.get("what")
    if not isinstance(what, list):
        return None
    kept = [w for w in what if isinstance(w, str) and w in LIVE_WHAT]
    if not kept:
        return None
    return json.dumps({"type": "updated", "what": kept}, separators=(",", ":"))


async def _safe_close(ws: WebSocket, code: int) -> None:
    if ws.application_state != WebSocketState.DISCONNECTED:
        with contextlib.suppress(Exception):
            await ws.close(code=code)


class Hub:
    """Per-app: socket count plus ONE shared pubsub subscriber."""

    def __init__(self) -> None:
        self.total = 0
        self.queues: set[asyncio.Queue] = set()
        self.task: asyncio.Task | None = None

    def register(self, redis) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=WS_QUEUE_MAX)
        self.queues.add(q)
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._subscriber(redis))
        return q

    async def unregister(self, q: asyncio.Queue) -> None:
        self.queues.discard(q)
        if not self.queues and self.task is not None:
            task, self.task = self.task, None
            task.cancel()
            with anyio.CancelScope(shield=True):
                await asyncio.gather(task, return_exceptions=True)

    def fan_out(self, data: str) -> None:
        for q in list(self.queues):
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                pass  # slow consumer: a dropped "please refetch" hint is harmless

    async def _subscriber(self, redis) -> None:
        backoff = 1.0
        while True:
            pubsub = redis.pubsub()
            try:
                await pubsub.subscribe(CHANNEL)
                backoff = 1.0
                while True:
                    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if msg is None:
                        await asyncio.sleep(0.05)
                        continue
                    payload = _relay_payload(msg.get("data"))
                    if payload is not None:
                        self.fan_out(payload)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                warn_rate_limited("ws-sub", f"ws subscriber error: {type(exc).__name__}")
            finally:
                with anyio.CancelScope(shield=True):
                    with contextlib.suppress(Exception):
                        await pubsub.unsubscribe(CHANNEL)
                    with contextlib.suppress(Exception):
                        await pubsub.aclose()
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, SUB_BACKOFF_MAX_S)


def _hub(app) -> Hub:
    hub = getattr(app.state, "ws_hub", None)
    if hub is None:
        hub = app.state.ws_hub = Hub()
    return hub


def _msg_size(msg: dict) -> int:
    if msg.get("text") is not None:
        return len(msg["text"].encode())
    return len(msg.get("bytes") or b"")


def _check_token_sync(app, token: str, now: datetime) -> int | None:
    try:
        with app.state.session_factory() as session:
            resolved = resolve_access(session, token, now)
    except Exception:  # any failure means unauthenticated
        return None
    return None if resolved is None else resolved[0].exp


async def _authenticate(ws: WebSocket) -> int | None:
    """Return the token's exp on success, None on any failure."""
    try:
        msg = await asyncio.wait_for(ws.receive(), timeout=WS_AUTH_TIMEOUT_S)
    except (TimeoutError, WebSocketDisconnect, RuntimeError):
        return None
    text = msg.get("text")
    if msg.get("type") != "websocket.receive" or text is None or _msg_size(msg) > WS_AUTH_MAX_BYTES:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("type") != "auth" or not isinstance(data.get("token"), str):
        return None
    return await run_in_threadpool(_check_token_sync, ws.app, data["token"], datetime.now(UTC))


async def _heartbeat(redis, key: str, member: str) -> None:
    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.zadd(key, {member: _now()}, xx=True)  # never resurrect a pruned member
            pipe.expire(key, int(2 * WS_PING_S + 60))
            await pipe.execute()
    except Exception as exc:
        warn_rate_limited("ws-heartbeat", f"ws heartbeat failed: {type(exc).__name__}")


async def _relay(ws: WebSocket, q: asyncio.Queue, redis, key: str, member: str | None) -> None:
    next_ping = time.monotonic() + WS_PING_S
    while True:
        remaining = next_ping - time.monotonic()
        if remaining <= 0:
            next_ping = time.monotonic() + WS_PING_S
            await ws.send_text(PING)
            if member is not None:
                await _heartbeat(redis, key, member)
            continue
        try:
            data = await asyncio.wait_for(q.get(), timeout=remaining)
        except TimeoutError:
            continue
        await ws.send_text(data)


async def _drain(ws: WebSocket) -> None:
    """Read and ignore client messages; nothing is retained."""
    while True:
        msg = await ws.receive()
        if msg["type"] == "websocket.disconnect":
            return


async def _sleep_until_exp(exp: int) -> None:
    await asyncio.sleep(_seconds_until(exp))


_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _origin_allowed(origin: str, host: str | None, allowed: list[str]) -> bool:
    """Configured list: exact match. Empty list ("same-origin only"): Origin must name the Host."""
    if allowed:
        return origin in allowed
    if not host:
        return False
    try:
        u = urlsplit(origin)
        o_host, o_port = u.hostname, u.port
    except ValueError:
        return False
    if u.scheme not in _DEFAULT_PORTS or not o_host:
        return False
    try:
        h = urlsplit("//" + host.strip())
        h_host, h_port = h.hostname, h.port
    except ValueError:
        return False
    if not h_host:
        return False
    return (o_host, o_port or _DEFAULT_PORTS[u.scheme]) == (h_host, h_port or _DEFAULT_PORTS[u.scheme])


@router.websocket("/api/ws/live")
async def live(ws: WebSocket) -> None:
    app = ws.app
    settings = app.state.settings

    origin = ws.headers.get("origin")
    if origin is not None and not _origin_allowed(origin, ws.headers.get("host"), settings.cors_origins):
        await ws.close(code=4403)  # before accept: nothing is ever sent to a foreign site
        return

    hub = _hub(app)
    # Over-limit closes happen AFTER accept: a pre-accept close becomes an
    # HTTP 403 and the client would never see the 4429 code.
    if hub.total >= WS_MAX_TOTAL:
        await ws.accept()
        await _safe_close(ws, 4429)
        return
    hub.total += 1  # no await since the check: atomic under the event loop
    member: str | None = None
    queue: asyncio.Queue | None = None
    try:
        # Inside the try: anything raising here must still release the slot.
        redis = get_redis(app)
        key = IP_KEY + _bucket(client_ip(ws))
        try:
            mid = uuid.uuid4().hex
            now = _now()
            ok = await redis.eval(
                _CONNECT_LUA, 1, key, now, now - _stale_after(), WS_MAX_PER_IP,
                int(2 * WS_PING_S + 60), mid,
            )
            if int(ok) == 1:
                member = mid
            else:
                await ws.accept()
                await _safe_close(ws, 4429)
                return
        except Exception as exc:  # fail open: notifications are low-value
            warn_rate_limited("ws-limit", f"ws connection limit unavailable: {type(exc).__name__}")

        if ws.application_state == WebSocketState.CONNECTING:
            await ws.accept()
        exp: int | None = None
        if not settings.public_read:
            exp = await _authenticate(ws)
            if exp is None:
                await _safe_close(ws, 4401)
                return

        queue = hub.register(redis)
        outcome = {"code": 1000}

        async def run(coro_fn, *args, code=None):
            try:
                await coro_fn(*args)
                if code is not None:
                    outcome["code"] = code
            except (WebSocketDisconnect, RuntimeError):
                pass
            except Exception as exc:
                log.warning("ws relay ended: %s", type(exc).__name__)
                outcome["code"] = 1011
            tg.cancel_scope.cancel()

        async with anyio.create_task_group() as tg:
            tg.start_soon(partial(run, _relay, ws, queue, redis, key, member))
            tg.start_soon(partial(run, _drain, ws))
            if exp is not None:
                tg.start_soon(partial(run, _sleep_until_exp, exp, code=4401))
        await _safe_close(ws, outcome["code"])
    finally:
        with anyio.CancelScope(shield=True):
            hub.total -= 1
            if queue is not None:
                await hub.unregister(queue)
            if member is not None:
                with contextlib.suppress(Exception):
                    await redis.zrem(key, member)
