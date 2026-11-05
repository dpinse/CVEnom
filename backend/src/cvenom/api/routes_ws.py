"""Live update WebSocket: /api/ws/live.

Auth is a first message (never a ?token= query: access logs record query
strings). Origin is checked before accept to stop cross-site hijacking.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from functools import partial
from datetime import datetime, timezone

import anyio
from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

from cvenom.auth.tokens import decode_access, session_is_active
from cvenom.live import CHANNEL

from .middleware import client_ip
from .ratelimit import get_redis, warn_rate_limited

log = logging.getLogger(__name__)
router = APIRouter()

WS_AUTH_TIMEOUT_S = 5.0
WS_PING_S = 30.0
WS_POLL_S = 1.0
WS_MAX_PER_IP = 5
WS_IP_TTL_S = 3600
WS_AUTH_MAX_BYTES = 4096
WS_CLIENT_MAX_BYTES = 1024
IP_KEY = "cvenom:ws:ip:"
PING = '{"type":"ping"}'


def _seconds_until(exp: int) -> float:
    return max(0.0, exp - time.time())


async def _safe_close(ws: WebSocket, code: int) -> None:
    if ws.application_state != WebSocketState.DISCONNECTED:
        with contextlib.suppress(Exception):
            await ws.close(code=code)


def _msg_size(msg: dict) -> int:
    if msg.get("text") is not None:
        return len(msg["text"].encode())
    return len(msg.get("bytes") or b"")


async def _authenticate(ws: WebSocket) -> int | None:
    """Return the token's exp on success, None on any failure."""
    try:
        msg = await asyncio.wait_for(ws.receive(), timeout=WS_AUTH_TIMEOUT_S)
    except (asyncio.TimeoutError, WebSocketDisconnect, RuntimeError):
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
    now = datetime.now(timezone.utc)
    try:
        with ws.app.state.session_factory() as session:
            claims = decode_access(session, data["token"], now)
            if not session_is_active(session, claims.sid, now):
                return None
    except Exception:  # InvalidToken or any failure: treat as unauthenticated
        return None
    return claims.exp


async def _relay(ws: WebSocket, redis) -> None:
    pubsub = redis.pubsub()
    try:
        await pubsub.subscribe(CHANNEL)
        last_ping = time.monotonic()
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=WS_POLL_S)
            if msg is not None:
                data = msg.get("data")
                if isinstance(data, bytes):
                    data = data.decode("utf-8", "replace")
                try:
                    parsed = json.loads(data)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, dict) and parsed.get("type") == "updated":
                    await ws.send_text(data)
            if time.monotonic() - last_ping >= WS_PING_S:
                last_ping = time.monotonic()
                await ws.send_text(PING)
            if msg is None:
                await asyncio.sleep(0.05)  # never spin if the backend returns immediately
    finally:
        with anyio.CancelScope(shield=True):  # cleanup must survive cancellation
            with contextlib.suppress(Exception):
                await pubsub.unsubscribe(CHANNEL)
            with contextlib.suppress(Exception):
                await pubsub.aclose()


async def _drain(ws: WebSocket) -> None:
    """Read and ignore client messages; nothing is retained."""
    while True:
        msg = await ws.receive()
        if msg["type"] == "websocket.disconnect":
            return


async def _sleep_until_exp(exp: int) -> None:
    await asyncio.sleep(_seconds_until(exp))


@router.websocket("/api/ws/live")
async def live(ws: WebSocket) -> None:
    app = ws.app
    settings = app.state.settings

    origin = ws.headers.get("origin")
    if origin is not None and settings.cors_origins and origin not in settings.cors_origins:
        await ws.close(code=4403)
        return

    redis = get_redis(app)
    key = IP_KEY + client_ip(ws)
    counted = False
    try:
        try:
            n = await redis.incr(key)
            counted = True
            await redis.expire(key, WS_IP_TTL_S)
            if n > WS_MAX_PER_IP:
                await ws.close(code=4429)
                return
        except Exception as exc:  # fail open: notifications are low-value
            warn_rate_limited("ws-limit", f"ws connection limit unavailable: {type(exc).__name__}")

        await ws.accept()
        exp: int | None = None
        if not settings.public_read:
            exp = await _authenticate(ws)
            if exp is None:
                await _safe_close(ws, 4401)
                return

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
            tg.start_soon(partial(run, _relay, ws, redis))
            tg.start_soon(partial(run, _drain, ws))
            if exp is not None:
                tg.start_soon(partial(run, _sleep_until_exp, exp, code=4401))
        await _safe_close(ws, outcome["code"])
    finally:
        if counted:
            with anyio.CancelScope(shield=True), contextlib.suppress(Exception):
                await redis.decr(key)
