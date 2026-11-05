"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware

from cvenom import secretbox
from cvenom.config import Settings, get_settings
from cvenom.db import session_scope

from .cache import ResponseCacheMiddleware
from .middleware import BodyLimitMiddleware, ErrorCatchMiddleware, SecurityHeadersMiddleware
from .ratelimit import get_redis
from .routes_alerts import router as alerts_router
from .routes_auth import router as auth_router
from .routes_read import CACHE_PATHS
from .routes_read import router as read_router
from .routes_ws import router as ws_router

log = logging.getLogger(__name__)


async def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        body = {"error": exc.detail["error"]}
    else:
        body = {"error": str(exc.detail)}
    return JSONResponse(body, status_code=exc.status_code, headers=getattr(exc, "headers", None))


async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Never echo `input`/`ctx`: request values may contain secrets.
    detail = []
    for e in exc.errors():
        etype = e.get("type", "")
        msg = e.get("msg", "")
        if etype in ("value_error", "assertion_error"):
            msg = "invalid value"  # custom validators may embed the input
        detail.append({"loc": list(e.get("loc", ()))[:2], "msg": msg, "type": etype})
    return JSONResponse({"error": "validation_error", "detail": detail}, status_code=422)


async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error", exc_info=exc)
    return JSONResponse({"error": "internal_error"}, status_code=500)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    yield
    if getattr(app.state, "redis_owned", False) and app.state.redis is not None:
        try:
            await app.state.redis.aclose()
        except Exception:  # shutdown must not fail on a dead connection
            log.warning("error closing redis client", exc_info=True)


def create_app(
    settings: Settings | None = None,
    *,
    redis=None,
    session_factory=None,
    cache_paths: dict[str, frozenset[str]] | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    try:
        secretbox.check_key(settings)
    except (secretbox.SecretsKeyMissing, ValueError) as exc:
        log.error("SECRETS_KEY unusable: %s", type(exc).__name__)
        if settings.require_secrets_key:
            raise
    if cache_paths is None:
        cache_paths = CACHE_PATHS
    docs = settings.api_docs
    app = FastAPI(
        lifespan=_lifespan,
        title="CVEnom",
        debug=False,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.redis = redis  # None: created lazily on first use (ratelimit.get_redis)
    app.state.redis_owned = False
    app.state.session_factory = session_factory or session_scope

    app.add_exception_handler(StarletteHTTPException, _http_exception)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unhandled)

    # add_middleware: last added is outermost. Order outer -> inner:
    # security headers, CORS, body limit, response cache, error catch, router.
    app.add_middleware(ErrorCatchMiddleware)
    if cache_paths and settings.public_read:  # {path prefix: allowed query params}
        app.add_middleware(
            ResponseCacheMiddleware, redis_getter=lambda: get_redis(app), paths=cache_paths
        )
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-CVEnom-CSRF"],
        )
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(auth_router)
    app.include_router(alerts_router)
    app.include_router(read_router)
    app.include_router(ws_router)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "public_read": settings.public_read}

    return app
