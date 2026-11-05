"""Task 15: delivery status listing and synthetic test-send."""

import base64
import os
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import fakeredis
import httpx
import pytest
from sqlalchemy import func, select

from cvenom import secretbox
from cvenom.alerts.sinks import SinkError, SinkNotConfigured
from cvenom.api import create_app, routes_alerts
from cvenom.auth.passwords import hash_password
from cvenom.auth.tokens import create_session, issue_access
from cvenom.config import get_settings
from cvenom.models import (
    AlertDelivery, AlertEvent, AlertRecipient, AlertRule, User,
)

HOOK_URL = "https://hooks.example.com/services/T000/SECRETPATHXYZ"
HOOK_SECRET = "supersecretvalue-1234567890"


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_app(db, sinks=None):
    @contextmanager
    def factory():
        yield db

    app = create_app(get_settings(), redis=fakeredis.FakeAsyncRedis(), session_factory=factory)
    if sinks is not None:
        app.state.sinks_factory = lambda: sinks
    return app


def client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app, client=("1.2.3.4", 1234)), base_url="https://test"
    )


def mk(db, role, email):
    u = User(email=email, password_hash=hash_password("correct horse battery"), role=role,
             is_active=True)
    db.add(u)
    db.flush()
    now = datetime.now(UTC)
    row, _ = create_session(db, u, now, "ua", "9.9.9.9")
    return {"Authorization": f"Bearer {issue_access(db, u, row.id, now)}"}


class Rec:
    """Fake sink recording calls; raises `exc` when given."""

    def __init__(self, exc=None, delay=0.0):
        self.exc, self.delay, self.calls = exc, delay, []

    def send(self, delivery, cve, rule, recipient):
        self.calls.append((delivery, cve, rule, recipient))
        if self.delay:
            time.sleep(self.delay)
        if self.exc is not None:
            raise self.exc


def rule_with(db, *, email=True, hook=False, enabled=True):
    rule = AlertRule(name="R", kind="kev_added", enabled=enabled)
    db.add(rule)
    db.flush()
    ids = {}
    if email:
        r = AlertRecipient(rule_id=rule.id, channel="email", email="ops@example.com")
        db.add(r)
        db.flush()
        ids["email"] = r.id
    if hook:
        r = AlertRecipient(
            rule_id=rule.id, channel="webhook",
            webhook_url=secretbox.encrypt(HOOK_URL.encode()),
            webhook_secret_enc=secretbox.encrypt(HOOK_SECRET.encode()))
        db.add(r)
        db.flush()
        ids["webhook"] = r.id
    return rule, ids


@pytest.fixture
def ctx(db_session):
    return (db_session, mk(db_session, "admin", "a@example.com"),
            mk(db_session, "member", "m@example.com"))


# ------------------------------------------------------------ deliveries


def seed_deliveries(db):
    rule1, ids1 = rule_with(db, hook=True)
    rule2, ids2 = rule_with(db)
    ev = AlertEvent(type="kev_added", cve_id="CVE-2024-0001", source="t")
    db.add(ev)
    db.flush()
    base = datetime(2026, 1, 1, tzinfo=UTC)
    specs = [
        (rule1, ids1["email"], "pending", "CVE-2024-0001"),
        (rule1, ids1["webhook"], "sent", "CVE-2024-0001"),
        (rule1, ids1["email"], "failed", "CVE-2024-0002"),
        (rule2, ids2["email"], "sent", "CVE-2024-0003"),
        (rule2, ids2["email"], "pending", "CVE-2024-0004"),
    ]
    for i, (rule, rid, status, cve) in enumerate(specs):
        db.add(AlertDelivery(
            event_id=ev.id, rule_id=rule.id, recipient_id=rid, cve_id=cve, status=status,
            created_at=base + timedelta(minutes=i),
            last_error="boom" if status == "failed" else None))
    db.flush()
    return rule1, rule2


async def test_deliveries_shape_filter_paginate(ctx):
    db, admin, member = ctx
    rule1, rule2 = seed_deliveries(db)
    app = make_app(db)
    async with client(app) as c:
        r = await c.get("/api/alerts/deliveries", headers=member)  # any authed user
        assert r.status_code == 200
        b = r.json()
        assert set(b) == {"items", "page", "page_size", "total"}
        assert b["total"] == 5 and b["page"] == 1
        assert [i["cve_id"] for i in b["items"]][0] == "CVE-2024-0004"  # newest first
        assert set(b["items"][0]) == {
            "id", "rule_id", "recipient_id", "channel", "cve_id", "status", "attempts",
            "last_error", "created_at", "sent_at", "next_attempt_at"}
        assert {i["channel"] for i in b["items"]} == {"email", "webhook"}
        for banned in ("ops@example.com", "hooks.example.com", "SECRETPATH", HOOK_SECRET):
            assert banned not in r.text

        r = await c.get("/api/alerts/deliveries?status=failed", headers=member)
        assert [i["last_error"] for i in r.json()["items"]] == ["boom"]
        r = await c.get(f"/api/alerts/deliveries?rule_id={rule2.id}", headers=member)
        assert r.json()["total"] == 2
        r = await c.get(f"/api/alerts/deliveries?rule_id={rule1.id}&status=sent", headers=member)
        assert [i["channel"] for i in r.json()["items"]] == ["webhook"]

        r = await c.get("/api/alerts/deliveries?page_size=2&page=2", headers=member)
        b = r.json()
        assert b["total"] == 5 and b["page"] == 2 and b["page_size"] == 2
        assert [i["cve_id"] for i in b["items"]] == ["CVE-2024-0002", "CVE-2024-0001"]
        r = await c.get("/api/alerts/deliveries?page_size=2&page=9", headers=member)
        assert r.json()["items"] == []


@pytest.mark.parametrize("qs", [
    "status=bogus", "status=SENT", "rule_id=abc", "page_size=101", "page_size=0", "page=0",
    "rule_id=0", "rule_id=99999999999",
])
async def test_deliveries_bad_params_422(ctx, qs):
    db, admin, member = ctx
    async with client(make_app(db)) as c:
        r = await c.get(f"/api/alerts/deliveries?{qs}", headers=member)
    assert r.status_code == 422
    assert set(r.json()) == {"error", "detail"}


async def test_deliveries_requires_auth(ctx):
    async with client(make_app(ctx[0])) as c:
        assert (await c.get("/api/alerts/deliveries")).status_code == 401


# ------------------------------------------------------------ test-send


async def test_test_send_per_recipient_results_and_no_rows(ctx):
    db, admin, member = ctx
    rule, ids = rule_with(db, hook=True)
    email, hook = Rec(), Rec()
    app = make_app(db, {"email": email, "webhook": hook})
    async with client(app) as c:
        r = await c.post(f"/api/alerts/rules/{rule.id}/test", headers=admin)
    assert r.status_code == 200
    assert r.json() == [
        {"recipient_id": ids["email"], "channel": "email", "ok": True, "error": None},
        {"recipient_id": ids["webhook"], "channel": "webhook", "ok": True, "error": None},
    ]
    delivery, cve, rl, rcp = email.calls[0]
    assert cve.cve_id == "CVE-0000-0000" and cve.summary == "CVEnom test alert"
    assert cve.cvss is None and rl.id == rule.id and rcp.channel == "email"
    assert delivery.status == "pending"
    assert db.scalar(select(func.count()).select_from(AlertDelivery)) == 0
    assert db.scalar(select(func.count()).select_from(AlertEvent)) == 0


async def test_test_send_error_policy(ctx):
    db, admin, member = ctx
    rule, ids = rule_with(db, hook=True)
    leaky = SinkError(f"POST {HOOK_URL} failed with {HOOK_SECRET}")
    app = make_app(db, {"email": Rec(SinkNotConfigured("smtp host is secret.example")),
                        "webhook": Rec(leaky)})
    async with client(app) as c:
        r = await c.post(f"/api/alerts/rules/{rule.id}/test", headers=admin)
    out = {x["channel"]: x for x in r.json()}
    assert out["email"] == {"recipient_id": ids["email"], "channel": "email", "ok": False,
                            "error": "not configured"}
    assert out["webhook"]["ok"] is False
    assert "[redacted]" in out["webhook"]["error"]
    for banned in (HOOK_SECRET, "SECRETPATHXYZ", "hooks.example.com/services"):
        assert banned not in r.text

    app = make_app(db, {"email": Rec(RuntimeError("password=hunter2")),
                        "webhook": Rec(SinkError("x" * 1000))})
    async with client(app) as c:
        r = await c.post(f"/api/alerts/rules/{rule.id}/test", headers=admin)
    out = {x["channel"]: x for x in r.json()}
    assert out["email"]["error"] == "RuntimeError"
    assert len(out["webhook"]["error"]) == 300
    assert "hunter2" not in r.text
    assert db.scalar(select(func.count()).select_from(AlertDelivery)) == 0


async def test_test_send_missing_sink_is_not_configured(ctx):
    db, admin, _ = ctx
    rule, ids = rule_with(db)
    async with client(make_app(db, {})) as c:
        r = await c.post(f"/api/alerts/rules/{rule.id}/test", headers=admin)
    assert r.json()[0]["error"] == "not configured" and r.json()[0]["ok"] is False


async def test_test_send_authz_and_404(ctx):
    db, admin, member = ctx
    rule, _ = rule_with(db)
    sink = Rec()
    app = make_app(db, {"email": sink})
    async with client(app) as c:
        assert (await c.post(f"/api/alerts/rules/{rule.id}/test",
                             headers=member)).status_code == 403
        assert (await c.post(f"/api/alerts/rules/{rule.id}/test")).status_code == 401
        assert (await c.post("/api/alerts/rules/999999/test", headers=admin)).status_code == 404
        assert (await c.post("/api/alerts/rules/99999999999/test",
                             headers=admin)).status_code == 404
    assert sink.calls == []


async def test_test_send_rate_limit_is_5_per_minute_per_admin(ctx):
    db, admin, member = ctx
    rule, _ = rule_with(db)
    app = make_app(db, {"email": Rec()})
    other_admin = mk(db, "admin", "a2@example.com")
    async with client(app) as c:
        codes = [(await c.post(f"/api/alerts/rules/{rule.id}/test", headers=admin)).status_code
                 for _ in range(6)]
        assert codes == [200] * 5 + [429]
        assert (await c.post(f"/api/alerts/rules/{rule.id}/test",
                             headers=other_admin)).status_code == 200
        # other endpoints use a different bucket
        assert (await c.get("/api/alerts/rules", headers=admin)).status_code == 200


async def test_test_send_overall_timeout(ctx, monkeypatch):
    db, admin, _ = ctx
    rule, _ = rule_with(db)
    monkeypatch.setattr(routes_alerts, "TEST_SEND_TIMEOUT_S", 0.2)
    app = make_app(db, {"email": Rec(delay=1.0)})
    async with client(app) as c:
        r = await c.post(f"/api/alerts/rules/{rule.id}/test", headers=admin)
    assert r.status_code == 504 and r.json() == {"error": "timeout"}
    assert db.scalar(select(func.count()).select_from(AlertDelivery)) == 0


def test_default_sinks_factory_is_build_sinks(db_session):
    from cvenom.alerts.sinks import build_sinks

    assert make_app(db_session).state.sinks_factory is build_sinks
