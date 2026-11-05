"""Redis fixed-window rate limiting (FastAPI dependencies).

Failure policy when Redis errors: scopes in FAIL_CLOSED_SCOPES return 503
(credential-stuffing protection must not silently vanish); every other scope
fails open with a warning rate-limited to once per 60 s per process.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Literal

from fastapi import Depends, HTTPException, Request
from redis.exceptions import RedisError

from cvenom.models import User

from .deps import try_current_user
from .middleware import client_ip

log = logging.getLogger(__name__)

FAIL_CLOSED_SCOPES = frozenset({"login", "auth", "mfa"})
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

        app.state.redis = aioredis.from_url(
            app.state.settings.redis_url, socket_timeout=5, socket_connect_timeout=5
        )
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


def rate_limit(
    scope: str, identity: Literal["auto", "ip"] = "auto", *, per_min: str | None = None
):
    """Dependency: valid user -> bucket u:{id} (authed limit); anonymous OR an
    invalid token -> bucket ip:{ip} (anon limit). Identity is resolved without
    raising, so bad-token floods are counted; the 401 is raised after counting
    (429 wins when the bucket is exhausted). No-Authorization requests do no DB
    work. If ResponseCacheMiddleware already counted this scope for the
    request's IP bucket, an anonymous request is not counted a second time.

    identity="ip": never inspects Authorization (a stale bearer must not break
    endpoints like refresh), always keys ip:{client_ip}, never raises 401.

    per_min: name of a Settings attribute that replaces BOTH the authed and
    anonymous per-minute limits for this scope (e.g. a stricter dedicated bucket)."""

    if identity == "ip":

        async def ip_dependency(request: Request) -> None:
            if request.scope.get(COUNTED_KEY) != scope:
                await _check(
                    request,
                    scope,
                    f"ip:{client_ip(request)}",
                    request.app.state.settings.rate_anon_per_min,
                    60,
                )

        ip_dependency.cvenom_rate_limit_scope = scope  # type: ignore[attr-defined]
        return ip_dependency

    async def dependency(
        request: Request, resolved: tuple[User | None, bool] = Depends(try_current_user)
    ) -> None:
        user, failed = resolved
        settings = request.app.state.settings
        authed = anon = getattr(settings, per_min) if per_min else None
        if user is not None:
            limit = authed if authed is not None else settings.rate_authed_per_min
            await _check(request, scope, f"u:{user.id}", limit, 60)
            return
        if request.scope.get(COUNTED_KEY) != scope:
            limit = anon if anon is not None else settings.rate_anon_per_min
            await _check(request, scope, f"ip:{client_ip(request)}", limit, 60)
        if failed:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Marker for the structural test asserting limiters run before auth deps.
    dependency.cvenom_rate_limit_scope = scope  # type: ignore[attr-defined]
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


# ---------------------------------------------------------------- MFA attempts

MFA_WINDOW_S = 900  # 15 minutes
# Give back one reserved attempt; never below zero and never creates a key.
_REFUND_LUA = """
local c = tonumber(redis.call('GET', KEYS[1]) or '0')
if c > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
"""


class MfaAttempt:
    """Failed second-factor attempts, counted per IP and per user (5 per 15 min each).

    Each attempt RESERVES a slot (atomic INCR) before any code is checked, so a burst of
    concurrent guesses can never exceed the limit; a successful attempt gives its slots
    back. The 'mfa' scope fails closed (503) when Redis is unavailable."""

    def __init__(self, request: Request) -> None:
        self.request = request
        self.keys: list[str] = []

    async def _take(self, ident: str, limit: int) -> None:
        await _check(self.request, "mfa", ident, limit, MFA_WINDOW_S)
        self.keys.append(f"cvenom:rl:mfa:{ident}")

    async def add_user(self, user_id: int) -> None:
        await self._take(f"user:{user_id}", self.request.app.state.settings.rate_mfa_per_15min_user)

    async def refund(self) -> None:
        redis = get_redis(self.request.app)
        for key in self.keys:
            try:
                await redis.eval(_REFUND_LUA, 1, key)
            except (RedisError, OSError):
                warn_rate_limited("rl-refund", "rate limiter unavailable; mfa refund skipped")
        self.keys.clear()


async def reserve_mfa_attempt(request: Request, *, ip: str) -> MfaAttempt:
    attempt = MfaAttempt(request)
    await attempt._take(f"ip:{ip}", request.app.state.settings.rate_mfa_per_15min_ip)
    return attempt
