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

from redis.exceptions import RedisError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .ratelimit import warn_rate_limited

CACHE_CONTROL = b"public, max-age=30"


class ResponseCacheMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        redis_getter: Callable[[], object],
        paths: tuple[str, ...],
        ttl: int = 30,
        max_bytes: int = 1_048_576,
    ) -> None:
        self.app = app
        self.redis_getter = redis_getter
        self.paths = tuple(p.rstrip("/") for p in paths)
        self.ttl = ttl
        self.max_bytes = max_bytes

    def _applies(self, scope: Scope) -> bool:
        if scope["method"] != "GET":
            return False
        path: str = scope.get("path", "")
        if not any(path == p or path.startswith(p + "/") for p in self.paths):
            return False
        names = {k.lower() for k, _ in scope.get("headers", [])}
        return b"authorization" not in names and b"cookie" not in names

    @staticmethod
    def _key(scope: Scope) -> str:
        qs = scope.get("query_string", b"").decode("latin-1")
        norm = urlencode(sorted(parse_qsl(qs, keep_blank_values=True)))
        raw = f"{scope.get('path', '')}?{norm}"
        return "cvenom:cache:" + hashlib.sha256(raw.encode()).hexdigest()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._applies(scope):
            await self.app(scope, receive, send)
            return

        key = self._key(scope)
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
                    (k, v) for k, v in headers if k.lower() not in (b"cache-control", b"x-cache")
                ]
                headers += [(b"cache-control", CACHE_CONTROL), (b"x-cache", b"MISS")]
            except (RedisError, OSError, UnicodeDecodeError):
                warn_rate_limited("cache", "response cache unavailable; not storing")
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body})
