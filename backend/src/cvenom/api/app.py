"""FastAPI application factory."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware

from cvenom.config import Settings, get_settings
from cvenom.db import session_scope

from .middleware import BodyLimitMiddleware, ErrorCatchMiddleware, SecurityHeadersMiddleware

log = logging.getLogger(__name__)


async def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        body = {"error": exc.detail["error"]}
    else:
        body = {"error": str(exc.detail)}
    return JSONResponse(body, status_code=exc.status_code, headers=getattr(exc, "headers", None))


async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Never echo `input`/`ctx`: request values may contain secrets.
    detail = [
        {"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
        for e in exc.errors()
    ]
    return JSONResponse({"error": "validation_error", "detail": detail}, status_code=422)


async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error", exc_info=exc)
    return JSONResponse({"error": "internal_error"}, status_code=500)


def create_app(settings: Settings | None = None, *, redis=None, session_factory=None) -> FastAPI:
    settings = settings or get_settings()
    docs = settings.api_docs
    app = FastAPI(
        title="CVEnom",
        debug=False,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.redis = redis
    app.state.session_factory = session_factory or session_scope

    app.add_exception_handler(StarletteHTTPException, _http_exception)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unhandled)

    # add_middleware: last added is outermost. Order outer -> inner:
    # security headers, body limit, CORS, error catch, router.
    app.add_middleware(ErrorCatchMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-CVEnom-CSRF"],
        )
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "public_read": settings.public_read}

    return app
