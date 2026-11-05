"""Pure-ASGI security middleware and client-IP resolution (no BaseHTTPMiddleware)."""

from __future__ import annotations

import ipaddress
import json
import logging

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger(__name__)

CSP = "default-src 'none'; frame-ancestors 'none'"
_STATIC_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", CSP.encode()),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
)


def _json_body(status: int, payload: dict) -> tuple[Message, Message]:
    body = json.dumps(payload).encode()
    start = {
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    }
    return start, {"type": "http.response.body", "body": body}


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        req_headers = {k.lower() for k, _ in scope.get("headers", [])}
        force_no_store = path.startswith("/api/auth") or b"authorization" in req_headers

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                drop = {name for name, _ in _STATIC_HEADERS}
                if force_no_store:
                    drop.add(b"cache-control")
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in drop]
                headers.extend(_STATIC_HEADERS)
                if force_no_store:
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodyLimitMiddleware:
    """413 on oversize Content-Length or oversize streamed bodies."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def reject() -> None:
            start, body = _json_body(413, {"error": "payload_too_large"})
            await send(start)
            await send(body)

        for k, v in scope.get("headers", []):
            if k.lower() == b"content-length":
                try:
                    declared = int(v)
                except ValueError:
                    declared = 0
                if declared > self.max_bytes:
                    await reject()
                    return

        seen = 0
        rejected = False
        started = False

        async def receive_wrapper() -> Message:
            nonlocal seen, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    rejected = True
                    if not started:
                        await reject()
                    return {"type": "http.disconnect"}
            return message

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if rejected and not started:
                return  # our 413 already went out; drop the app's output
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, receive_wrapper, send_wrapper)


class ErrorCatchMiddleware:
    """Turn any unhandled exception into a generic 500 inside the middleware
    stack, so CORS and security headers still apply. Never leaks details."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            log.exception("unhandled error")
            if not started:
                start, body = _json_body(500, {"error": "internal_error"})
                await send(start)
                await send(body)


def _parse_ip(value: str | None):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    """Resolve the real client IP. Forwarding headers are honoured only when
    the socket peer is inside settings.trusted_proxy_cidrs."""
    peer = request.client.host if request.client else "0.0.0.0"
    settings = request.app.state.settings
    nets = [ipaddress.ip_network(c, strict=False) for c in settings.trusted_proxy_cidrs]

    def trusted(ip) -> bool:
        return any(ip.version == n.version and ip in n for n in nets)

    peer_ip = _parse_ip(peer)
    if peer_ip is None or not trusted(peer_ip):
        return peer

    cf = _parse_ip(request.headers.get("cf-connecting-ip"))
    if cf is not None:
        return str(cf)

    xff = request.headers.get("x-forwarded-for", "")
    for entry in reversed(xff.split(",")):
        ip = _parse_ip(entry)
        if ip is None or trusted(ip):
            continue
        return str(ip)
    return peer
