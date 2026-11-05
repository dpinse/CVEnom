"""Redis fixed-window rate limiting (FastAPI dependencies).

Failure policy when Redis errors: scopes in FAIL_CLOSED_SCOPES return 503
(credential-stuffing protection must not silently vanish); every other scope
fails open with a warning rate-limited to once per 60 s per process.
"""

from __future__ import annotations

import hashlib
import logging
import time

from fastapi import Depends, HTTPException, Request
from redis.exceptions import RedisError

from cvenom.models import User

from .deps import try_current_user
from .middleware import client_ip

log = logging.getLogger(__name__)

FAIL_CLOSED_SCOPES = frozenset({"login", "auth"})
_WARN_INTERVAL_S = 60.0
_last_warn: dict[str, float] = {}

_HIT_LUA = """
local c = redis.call('INCR', KEYS[1])
local t = redis.call('PTTL', KEYS[1])
if c == 1 or t < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
  t = tonumber(ARGV[1]) * 1000
end
return {c, t}
"""


def warn_rate_limited(name: str, msg: str) -> None:
    """Log a WARNING at most once per 60 s per process for each `name`."""
    now = time.monotonic()
    last = _last_warn.get(name)
    if last is None or now - last >= _WARN_INTERVAL_S:
        _last_warn[name] = now
        log.warning(msg)


def get_redis(app):
    """Return the app's Redis client, creating the production one lazily."""
    if app.state.redis is None:
        import redis.asyncio as aioredis

        app.state.redis = aioredis.from_url(app.state.settings.redis_url)
        app.state.redis_owned = True
    return app.state.redis


class RateLimiter:
    def __init__(self, redis) -> None:
        self.redis = redis

    async def hit(self, key: str, limit: int, window_s: int) -> tuple[bool, int]:
        count, ttl = await self.redis.eval(_HIT_LUA, 1, key, window_s)
        count, ttl = int(count), int(ttl)
        retry_after = max(1, -(-ttl // 1000))  # PTTL ms, ceil; never 0
        return count <= limit, retry_after


def _unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail={"error": "unavailable"})


def _limited(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail={"error": "rate_limited"},
        headers={"Retry-After": str(retry_after)},
    )


async def _check(request: Request, scope: str, ident: str, limit: int, window_s: int) -> None:
    key = f"cvenom:rl:{scope}:{ident}"
    try:
        allowed, retry_after = await RateLimiter(get_redis(request.app)).hit(key, limit, window_s)
    except (RedisError, OSError):
        if scope in FAIL_CLOSED_SCOPES:
            log.error("rate limiter unavailable; failing closed for scope %s", scope)
            raise _unavailable() from None
        warn_rate_limited("rl", "rate limiter unavailable; failing open")
        return
    if not allowed:
        raise _limited(retry_after)


COUNTED_KEY = "cvenom_rl_counted"


def rate_limit(scope: str):
    """Dependency: valid user -> bucket u:{id} (authed limit); anonymous OR an
    invalid token -> bucket ip:{ip} (anon limit). Identity is resolved without
    raising, so bad-token floods are counted; the 401 is raised after counting
    (429 wins when the bucket is exhausted). No-Authorization requests do no DB
    work. If ResponseCacheMiddleware already counted this scope for the
    request's IP bucket, an anonymous request is not counted a second time."""

    async def dependency(
        request: Request, resolved: tuple[User | None, bool] = Depends(try_current_user)
    ) -> None:
        user, failed = resolved
        settings = request.app.state.settings
        if user is not None:
            await _check(request, scope, f"u:{user.id}", settings.rate_authed_per_min, 60)
            return
        if request.scope.get(COUNTED_KEY) != scope:
            await _check(
                request, scope, f"ip:{client_ip(request)}", settings.rate_anon_per_min, 60
            )
        if failed:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

    return dependency


async def enforce_login_limits(request: Request, email: str) -> None:
    settings = request.app.state.settings
    normalized = email.strip().lower()
    digest = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()
    await _check(
        request, "login", f"login-ip:{client_ip(request)}", settings.rate_login_per_15min_ip, 900
    )
    await _check(
        request, "login", f"login-email:{digest}", settings.rate_login_per_15min_email, 900
    )
