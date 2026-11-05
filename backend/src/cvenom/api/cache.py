"""Short-TTL cache of anonymous public GET JSON responses (pure ASGI).

Install order (outer -> inner): SecurityHeaders, CORS, BodyLimit,
ResponseCache, ErrorCatch, router. Only anonymous requests (no Authorization
or Cookie header) are served from / stored in the cache, so the SecurityHeaders
no-store rule for authed requests never conflicts. A Redis error bypasses the
cache and never fails the request.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode

from fastapi import HTTPException
from redis.exceptions import RedisError
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .middleware import client_ip
from .ratelimit import COUNTED_KEY, _check, warn_rate_limited

CACHE_CONTROL = b"public, max-age=30"
VARY = b"Origin"


class ResponseCacheMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        redis_getter: Callable[[], object],
        paths: dict[str, frozenset[str]],
        ttl: int = 30,
        max_bytes: int = 262_144,
    ) -> None:
        # paths: cached path prefix -> ALLOWED query-param names. A request with
        # any other param bypasses the cache (bounds the keyspace so attackers
        # cannot fill Redis with distinct-query entries).
        self.app = app
        self.redis_getter = redis_getter
        self.paths = {p.rstrip("/"): frozenset(v) for p, v in paths.items()}
        self.ttl = ttl
        self.max_bytes = max_bytes

    def _key_for(self, scope: Scope) -> str | None:
        """Cache key, or None when this request must bypass the cache."""
        if scope["method"] != "GET":
            return None
        path: str = scope.get("path", "")
        matches = [p for p in self.paths if path == p or path.startswith(p + "/")]
        if not matches:
            return None
        allowed = self.paths[max(matches, key=len)]
        names = {k.lower() for k, _ in scope.get("headers", [])}
        if b"authorization" in names or b"cookie" in names:
            return None
        qs = scope.get("query_string", b"").decode("latin-1")
        pairs = parse_qsl(qs, keep_blank_values=True)
        if any(k not in allowed for k, _ in pairs):
            return None
        # stable sort by name only: repeated-key value order is preserved
        norm = urlencode(sorted(pairs, key=lambda kv: kv[0]))
        raw = f"{path}?{norm}"
        return "cvenom:cache:" + hashlib.sha256(raw.encode()).hexdigest()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        key = self._key_for(scope) if scope["type"] == "http" else None
        if key is None:
            await self.app(scope, receive, send)
            return

        # Count this anonymous request in the shared `read` IP bucket BEFORE the
        # cache lookup so HIT floods are limited. Mark the scope so the handler's
        # rate_limit("read") dependency does not count the same request again.
        request = Request(scope)
        try:
            await _check(
                request,
                "read",
                f"ip:{client_ip(request)}",
                request.app.state.settings.rate_anon_per_min,
                60,
            )
        except HTTPException as exc:
            body = json.dumps(exc.detail).encode()
            hdrs = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
            hdrs += [(k.lower().encode(), v.encode()) for k, v in (exc.headers or {}).items()]
            await send({"type": "http.response.start", "status": exc.status_code, "headers": hdrs})
            await send({"type": "http.response.body", "body": body})
            return
        scope[COUNTED_KEY] = "read"
        try:
            redis = self.redis_getter()
            cached = await redis.get(key)
        except (RedisError, OSError):
            warn_rate_limited("cache", "response cache unavailable; bypassing")
            await self.app(scope, receive, send)
            return

        if cached is not None:
            try:
                entry = json.loads(cached)
                body = entry["body"].encode()
                ctype = entry["ct"].encode("latin-1")
            except (ValueError, KeyError, TypeError, AttributeError):
                entry = None
            if entry is not None:
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", ctype),
                            (b"content-length", str(len(body)).encode()),
                            (b"cache-control", CACHE_CONTROL),
                            (b"x-cache", b"HIT"),
                            (b"vary", VARY),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return

        start: Message | None = None
        chunks: list[bytes] = []

        async def capture(message: Message) -> None:
            nonlocal start
            if message["type"] == "http.response.start":
                start = message
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))

        await self.app(scope, receive, capture)
        if start is None:
            return
        body = b"".join(chunks)
        headers = list(start.get("headers", []))
        lower = {k.lower(): v for k, v in headers}
        ctype = lower.get(b"content-type", b"")
        cacheable = (
            start["status"] == 200
            and ctype.split(b";")[0].strip().lower() == b"application/json"
            and b"set-cookie" not in lower
            and len(body) <= self.max_bytes
        )
        if cacheable:
            try:
                payload = json.dumps({"ct": ctype.decode("latin-1"), "body": body.decode()})
                await redis.set(key, payload, ex=self.ttl)
                headers = [
                    (k, v) for k, v in headers if k.lower() not in (b"cache-control", b"x-cache", b"vary")
                ]
                headers += [(b"cache-control", CACHE_CONTROL), (b"x-cache", b"MISS"), (b"vary", VARY)]
            except (RedisError, OSError, UnicodeDecodeError):
                warn_rate_limited("cache", "response cache unavailable; not storing")
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body})
