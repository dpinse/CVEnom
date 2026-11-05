"""I1: every API route counts a request against a limiter BEFORE any auth
dependency can answer 401, so invalid-token / anonymous floods are throttled."""

import base64
import inspect
import os
from contextlib import contextmanager

import fakeredis
import httpx
import pytest
from fastapi.routing import APIRoute

from cvenom.api import create_app
from cvenom.api import deps
from cvenom.api import routes_auth
from cvenom.config import get_settings


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_app(db_session, **overrides):
    settings = get_settings().model_copy(update=overrides)

    @contextmanager
    def factory():
        yield db_session

    return create_app(settings, redis=fakeredis.FakeAsyncRedis(), session_factory=factory)


def client(app, peer=("1.2.3.4", 1234)):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=peer), base_url="https://test"
    )


BAD = {"Authorization": "Bearer junk"}


@pytest.mark.parametrize(
    "path,headers,overrides",
    [
        ("/api/lanes", BAD, {}),
        ("/api/cves", BAD, {}),
        ("/api/lanes", {}, {"public_read": False}),
        ("/api/auth/me", BAD, {}),
        ("/api/auth/sessions", BAD, {}),
    ],
)
async def test_61st_unauthenticated_request_is_429(db_session, path, headers, overrides):
    app = make_app(db_session, **overrides)
    async with client(app) as c:
        for _ in range(60):
            assert (await c.get(path, headers=headers)).status_code == 401
        r = await c.get(path, headers=headers)
    assert r.status_code == 429, path
    assert "retry-after" in r.headers


AUTH_DEPS = {deps.public_or_user, deps.require_user, deps.require_admin, deps.current_user}
# Login enforces its limiters inside the handler (they need the body's email)
# and has no auth dependency; asserted separately below.
EXEMPT = {"/api/health", "/api/auth/login"}


def _execution_order(dependant) -> list:
    """Dependency calls in the order FastAPI runs them (sub-deps first)."""
    out = []
    for sub in dependant.dependencies:
        out.extend(_execution_order(sub))
        out.append(sub.call)
    return out


def _is_limiter(call) -> bool:
    return getattr(call, "cvenom_rate_limit_scope", None) is not None


def _http_routes(app):
    """(path, methods, dependant) for every HTTP API route, including those
    reached through include_router (FastAPI wraps them in _IncludedRouter)."""
    for route in app.routes:
        if isinstance(route, APIRoute):
            yield route.path, route.methods, route.dependant
            continue
        contexts = getattr(route, "effective_route_contexts", None)
        if contexts is None:
            continue
        for ctx in contexts():
            if isinstance(ctx.original_route, APIRoute):
                yield ctx.path, ctx.methods, ctx.dependant


def test_every_api_route_rate_limits_before_auth(db_session):
    app = make_app(db_session, api_docs=False)
    checked = 0
    for path, methods, dependant in _http_routes(app):
        if not path.startswith("/api") or path in EXEMPT:
            continue
        calls = _execution_order(dependant)
        limiter_at = [i for i, c in enumerate(calls) if _is_limiter(c)]
        assert limiter_at, f"{path} {methods} has no rate_limit dependency"
        auth_at = [i for i, c in enumerate(calls) if c in AUTH_DEPS]
        if auth_at:
            assert limiter_at[0] < auth_at[0], f"{path} {methods}: auth before limiter"
        checked += 1
    assert checked >= 20


NEW_ROUTES = {
    ("/api/auth/users", "GET"), ("/api/auth/users/{user_id}", "PATCH"),
    ("/api/auth/users/{user_id}/sessions/revoke", "POST"),
    ("/api/auth/users/{user_id}/reset", "POST"), ("/api/auth/password", "POST"),
    ("/api/auth/invites", "GET"), ("/api/auth/invites/{invite_id}", "DELETE"),
    ("/api/alerts/deliveries", "GET"), ("/api/alerts/rules/{rule_id}/test", "POST"),
}


def test_task15_routes_exist_and_limit_before_auth(db_session):
    app = make_app(db_session, api_docs=False)
    seen = set()
    for path, methods, dependant in _http_routes(app):
        for m in methods:
            if (path, m) not in NEW_ROUTES:
                continue
            seen.add((path, m))
            calls = _execution_order(dependant)
            limiter_at = [i for i, c in enumerate(calls) if _is_limiter(c)]
            auth_at = [i for i, c in enumerate(calls) if c in AUTH_DEPS]
            assert limiter_at and auth_at and limiter_at[0] < auth_at[0], (path, m)
    assert seen == NEW_ROUTES


def test_alert_test_route_has_its_own_limiter_scope(db_session):
    app = make_app(db_session, api_docs=False)
    for path, methods, dependant in _http_routes(app):
        if path == "/api/alerts/rules/{rule_id}/test":
            scopes = [c.cvenom_rate_limit_scope for c in _execution_order(dependant)
                      if _is_limiter(c)]
            assert scopes == ["api", "alert-test"]
            break
    else:
        pytest.fail("route missing")


def test_login_handler_limits_before_any_db_work():
    src = inspect.getsource(routes_auth.login)
    assert src.index("enforce_login_limits") < src.index("run_in_threadpool(_login_sync")


def test_mfa_handlers_reserve_an_attempt_before_any_db_work():
    from cvenom.api import routes_mfa

    for handler in (routes_mfa.verify, routes_mfa.enroll_finish):
        src = inspect.getsource(handler)
        assert src.index("reserve_mfa_attempt(request, ip=") < src.index("run_in_threadpool"), handler


def test_mfa_scope_fails_closed():
    from cvenom.api.ratelimit import FAIL_CLOSED_SCOPES

    assert "mfa" in FAIL_CLOSED_SCOPES


MFA_AUTHED_ROUTES = {
    ("/api/auth/mfa", "GET"),
    ("/api/auth/mfa/recovery-codes", "POST"),
    ("/api/auth/users/{user_id}/mfa/reset", "POST"),
}


def test_mfa_account_and_admin_routes_limit_before_auth(db_session):
    app = make_app(db_session, api_docs=False)
    seen = set()
    for path, methods, dependant in _http_routes(app):
        for m in methods:
            if (path, m) not in MFA_AUTHED_ROUTES:
                continue
            seen.add((path, m))
            calls = _execution_order(dependant)
            limiter_at = [i for i, c in enumerate(calls) if _is_limiter(c)]
            auth_at = [i for i, c in enumerate(calls) if c in AUTH_DEPS]
            assert limiter_at and auth_at and limiter_at[0] < auth_at[0], (path, m)
    assert seen == MFA_AUTHED_ROUTES


def test_regenerate_reserves_an_attempt_before_checking_the_code():
    from cvenom.api import routes_mfa

    src = inspect.getsource(routes_mfa.regenerate_recovery_codes)
    assert src.index("reserve_mfa_attempt(") < src.index("run_in_threadpool")
