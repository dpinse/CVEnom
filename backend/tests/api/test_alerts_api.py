import base64
import os
import socket

import fakeredis
import httpx
import pytest
from sqlalchemy import select

from cvenom import secretbox
from cvenom.alerts import webhook
from cvenom.api import create_app
from cvenom.auth.passwords import hash_password
from cvenom.auth.tokens import create_session, issue_access
from cvenom.config import get_settings
from cvenom.models import AlertRecipient, AlertRule, User
from contextlib import contextmanager
from datetime import UTC, datetime

URL = "https://hooks.example.com/services/T000/B000/XXXSECRETPATH?token=querysecret"
PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()

    def dns(host, port, *a, **k):
        ip = {"localhost": "127.0.0.1", "internal.example.com": "10.0.0.7"}.get(host, PUBLIC_IP)
        return [(socket.AF_INET, 0, 0, "", (ip, port))]

    monkeypatch.setattr(webhook.socket, "getaddrinfo", dns)
    yield
    get_settings.cache_clear()


def make_app(db):
    @contextmanager
    def factory():
        yield db

    return create_app(get_settings(), redis=fakeredis.FakeAsyncRedis(), session_factory=factory)


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


@pytest.fixture
def ctx(db_session):
    admin = mk(db_session, "admin", "a@example.com")
    member = mk(db_session, "member", "m@example.com")
    return make_app(db_session), admin, member, db_session


def email_rule(**over):
    body = {
        "name": "KEV",
        "kind": "kev_added",
        "recipients": [{"channel": "email", "email": "Ops@Example.com"}],
    }
    body.update(over)
    return body


def hook_rule(url=URL, **extra):
    return {
        "name": "hook",
        "kind": "cvss_min",
        "threshold": 9.0,
        "recipients": [{"channel": "webhook", "url": url, **extra}],
    }


async def test_create_email_rule_and_shape(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", json=email_rule(), headers=admin)
        assert r.status_code == 201
        b = r.json()
        assert set(b) == {"id", "name", "kind", "threshold", "keyword", "enabled",
                          "created_at", "recipients", "recipient_count"}
        assert b["recipients"][0]["email"] == "ops@example.com"
        assert b["recipients"][0]["channel"] == "email"
        assert db.scalars(select(AlertRecipient)).one().email == "ops@example.com"


async def test_member_forbidden_on_writes_ok_on_reads(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", json=email_rule(), headers=admin)).json()["id"]
        rcp = (await c.post(f"/api/alerts/rules/{rid}/recipients",
                            json={"channel": "email", "email": "x@example.com"},
                            headers=admin)).json()["id"]
        assert (await c.post("/api/alerts/rules", json=email_rule(), headers=member)
                ).status_code == 403
        assert (await c.patch(f"/api/alerts/rules/{rid}", json={"name": "n"}, headers=member)
                ).status_code == 403
        assert (await c.delete(f"/api/alerts/rules/{rid}", headers=member)).status_code == 403
        assert (await c.post(f"/api/alerts/rules/{rid}/recipients",
                             json={"channel": "email", "email": "y@example.com"},
                             headers=member)).status_code == 403
        assert (await c.delete(f"/api/alerts/rules/{rid}/recipients/{rcp}", headers=member)
                ).status_code == 403
        assert (await c.get("/api/alerts/rules", headers=member)).status_code == 200
        assert (await c.get(f"/api/alerts/rules/{rid}", headers=member)).status_code == 200
        assert (await c.get("/api/alerts/rules")).status_code == 401


async def test_member_rules_have_no_recipients_only_count(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        body = hook_rule()
        body["recipients"].append({"channel": "email", "email": "Ops@Example.com"})
        rid = (await c.post("/api/alerts/rules", json=body, headers=admin)).json()["id"]
        await c.post("/api/alerts/rules", json=email_rule(), headers=admin)
        paths = ["/api/alerts/rules", f"/api/alerts/rules/{rid}"]
        for path in paths:
            r = await c.get(path, headers=member)
            assert r.status_code == 200
            for banned in ("ops@example.com", "hooks.example.com", "SECRETPATH", "url_masked",
                           "recipients", "querysecret"):
                assert banned not in r.text.lower().replace("recipient_count", "")
            data = r.json()
            for rule in data if isinstance(data, list) else [data]:
                assert "recipients" not in rule and "recipient_count" in rule
        one = (await c.get(f"/api/alerts/rules/{rid}", headers=member)).json()
        assert one["recipient_count"] == 2
        listed = (await c.get("/api/alerts/rules", headers=member)).json()
        assert [x["recipient_count"] for x in listed] == [2, 1]


async def test_admin_rules_keep_recipients_and_count(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", json=email_rule(), headers=admin)).json()["id"]
        for path in ("/api/alerts/rules", f"/api/alerts/rules/{rid}"):
            r = await c.get(path, headers=admin)
            data = r.json()
            rule = data[0] if isinstance(data, list) else data
            assert rule["recipient_count"] == 1
            assert rule["recipients"][0]["email"] == "ops@example.com"


@pytest.mark.parametrize(
    "kind,threshold,keyword,ok",
    [
        ("kev_added", None, None, True),
        ("kev_added", 1.0, None, False),
        ("kev_added", None, "x", False),
        ("cvss_min", 7.5, None, True),
        ("cvss_min", 10, None, True),
        ("cvss_min", 0, None, True),
        ("cvss_min", 10.1, None, False),
        ("cvss_min", -0.1, None, False),
        ("cvss_min", None, None, False),
        ("cvss_min", 5, "k", False),
        ("epss_min", 0.5, None, True),
        ("epss_min", 1.1, None, False),
        ("epss_min", None, None, False),
        ("keyword", None, "  log4j ", True),
        ("keyword", None, "", False),
        ("keyword", None, "   ", False),
        ("keyword", None, "a" * 101, False),
        ("keyword", None, "a\x07b", False),
        ("keyword", None, None, False),
        ("keyword", 1.0, "k", False),
        ("nope", None, None, False),
    ],
)
async def test_kind_validation(ctx, kind, threshold, keyword, ok):
    app, admin, *_ = ctx
    body = email_rule(kind=kind, threshold=threshold, keyword=keyword)
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", json=body, headers=admin)
    assert r.status_code == (201 if ok else 422)
    if ok and kind == "keyword":
        assert r.json()["keyword"] == "log4j"


async def test_nan_inf_rejected(ctx):
    app, admin, *_ = ctx
    async with client(app) as c:
        for raw in ("NaN", "Infinity", "-Infinity"):
            body = (
                '{"name":"n","kind":"cvss_min","threshold":' + raw + ','
                '"recipients":[{"channel":"email","email":"a@example.com"}]}'
            )
            r = await c.post("/api/alerts/rules", content=body, headers={
                **admin, "Content-Type": "application/json"})
            assert r.status_code == 422


async def test_body_shape_validation(ctx):
    app, admin, *_ = ctx
    async with client(app) as c:
        post = lambda b: c.post("/api/alerts/rules", json=b, headers=admin)  # noqa: E731
        assert (await post(email_rule(name=""))).status_code == 422
        assert (await post(email_rule(name="n" * 201))).status_code == 422
        assert (await post(email_rule(recipients=[]))).status_code == 422
        many = [{"channel": "email", "email": f"u{i}@example.com"} for i in range(21)]
        assert (await post(email_rule(recipients=many))).status_code == 422
        assert (await post(email_rule(extra=1))).status_code == 422
        bad = [{"channel": "email", "email": "not-an-email"}]
        assert (await post(email_rule(recipients=bad))).status_code == 422
        mism = [{"channel": "email", "email": "a@example.com", "url": URL}]
        assert (await post(email_rule(recipients=mism))).status_code == 422
        mism2 = [{"channel": "webhook", "url": URL, "email": "a@example.com"}]
        assert (await post(email_rule(recipients=mism2))).status_code == 422
        short = [{"channel": "webhook", "url": URL, "secret": "short"}]
        assert (await post(email_rule(recipients=short))).status_code == 422
        assert (await post(email_rule(recipients=[{"channel": "sms"}]))).status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/h",
        "https://127.0.0.1/h",
        "https://169.254.169.254/latest",
        "https://[::1]/h",
        "https://user:pw@hooks.example.com/h",
        "https://localhost/h",
        "https://internal.example.com/h",
        "https://hooks.example.com:0/h",
    ],
)
async def test_unsafe_urls_422_and_nothing_stored(ctx, url):
    app, admin, member, db = ctx
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", json=hook_rule(url), headers=admin)
        assert r.status_code == 422
        assert r.json() == {"error": "unsafe_webhook_url"}
        assert db.scalars(select(AlertRule)).first() is None
        rid = (await c.post("/api/alerts/rules", json=email_rule(), headers=admin)).json()["id"]
        r = await c.post(f"/api/alerts/rules/{rid}/recipients",
                         json={"channel": "webhook", "url": url}, headers=admin)
        assert r.status_code == 422 and r.json() == {"error": "unsafe_webhook_url"}


async def test_secret_once_masked_and_encrypted(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", json=hook_rule(), headers=admin)
        assert r.status_code == 201
        rec = r.json()["recipients"][0]
        secret = rec["secret"]
        assert len(secret) >= 32
        assert rec["url_masked"] == "https://hooks.example.com/…"
        assert set(rec) == {"id", "channel", "url_masked", "secret"}
        rid = r.json()["id"]

        row = db.scalars(select(AlertRecipient)).one()
        assert row.webhook_secret_enc.startswith("v1:")
        assert secretbox.decrypt(row.webhook_secret_enc) == secret.encode()
        assert secret not in row.webhook_secret_enc

        later = [
            await c.get("/api/alerts/rules", headers=admin),
            await c.get(f"/api/alerts/rules/{rid}", headers=admin),
            await c.patch(f"/api/alerts/rules/{rid}", json={"name": "renamed"}, headers=admin),
        ]
        for resp in later:
            assert resp.status_code == 200
            t = resp.text
            assert secret not in t
            assert "XXXSECRETPATH" not in t and "querysecret" not in t
            assert "T000" not in t and row.webhook_secret_enc not in t
            assert "webhook_secret" not in t and "webhook_url" not in t
        assert later[0].json()[0]["recipients"][0] == {
            "id": rec["id"], "channel": "webhook", "url_masked": "https://hooks.example.com/…"
        }


async def test_supplied_secret_and_nondefault_port(ctx):
    app, admin, member, db = ctx
    supplied = "s" * 20
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", headers=admin, json=hook_rule(
            "https://hooks.example.com:8443/p", secret=supplied))
        rec = r.json()["recipients"][0]
        assert rec["secret"] == supplied
        assert rec["url_masked"] == "https://hooks.example.com:8443/…"
        assert secretbox.decrypt(db.scalars(select(AlertRecipient)).one().webhook_secret_enc
                                 ) == supplied.encode()


async def test_add_and_delete_recipient(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", json=email_rule(), headers=admin)).json()["id"]
        r = await c.post(f"/api/alerts/rules/{rid}/recipients", headers=admin,
                         json={"channel": "webhook", "url": URL})
        assert r.status_code == 201 and "secret" in r.json()
        new = r.json()["id"]
        got = (await c.get(f"/api/alerts/rules/{rid}", headers=admin)).json()
        assert len(got["recipients"]) == 2 and "secret" not in got["recipients"][1]
        assert (await c.delete(f"/api/alerts/rules/{rid}/recipients/{new}", headers=admin)
                ).status_code == 204
        assert len((await c.get(f"/api/alerts/rules/{rid}", headers=admin)).json()["recipients"]
                   ) == 1
        # recipients are not editable in place
        assert (await c.patch(f"/api/alerts/rules/{rid}/recipients/{new}", json={},
                              headers=admin)).status_code in (404, 405)


async def test_recipient_cap_on_add(ctx):
    app, admin, member, db = ctx
    recips = [{"channel": "email", "email": f"u{i}@example.com"} for i in range(20)]
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", json=email_rule(recipients=recips),
                            headers=admin)).json()["id"]
        r = await c.post(f"/api/alerts/rules/{rid}/recipients", headers=admin,
                         json={"channel": "email", "email": "z@example.com"})
        assert r.status_code == 422


async def test_not_found_and_foreign_ids(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        a = (await c.post("/api/alerts/rules", json=email_rule(), headers=admin)).json()
        b = (await c.post("/api/alerts/rules", json=email_rule(), headers=admin)).json()
        nf = {"error": "not_found"}
        for method, path, kw in [
            ("get", "/api/alerts/rules/99999", {}),
            ("get", f"/api/alerts/rules/{2**40}", {}),
            ("patch", "/api/alerts/rules/99999", {"json": {"name": "x"}}),
            ("delete", "/api/alerts/rules/99999", {}),
            ("post", "/api/alerts/rules/99999/recipients",
             {"json": {"channel": "email", "email": "q@example.com"}}),
            ("delete", f"/api/alerts/rules/{a['id']}/recipients/99999", {}),
            # recipient belongs to rule b, addressed through rule a
            ("delete", f"/api/alerts/rules/{a['id']}/recipients/{b['recipients'][0]['id']}", {}),
        ]:
            r = await getattr(c, method)(path, headers=admin, **kw)
            assert (r.status_code, r.json()) == (404, nf), path
        assert len((await c.get(f"/api/alerts/rules/{b['id']}", headers=admin)).json()[
            "recipients"]) == 1


async def test_patch_rules(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", headers=admin, json=email_rule(
            kind="cvss_min", threshold=7))).json()["id"]
        u = f"/api/alerts/rules/{rid}"
        r = await c.patch(u, json={"name": "new", "threshold": 9.5, "enabled": False},
                          headers=admin)
        assert r.status_code == 200
        assert (r.json()["name"], r.json()["threshold"], r.json()["enabled"]) == (
            "new", 9.5, False)
        assert (await c.patch(u, json={"threshold": 11}, headers=admin)).status_code == 422
        assert (await c.patch(u, json={"threshold": None}, headers=admin)).status_code == 422
        assert (await c.patch(u, json={"keyword": "x"}, headers=admin)).status_code == 422
        assert (await c.patch(u, json={"name": None}, headers=admin)).status_code == 422
        assert (await c.patch(u, json={"name": ""}, headers=admin)).status_code == 422
        # kind is immutable: extra-forbid
        r = await c.patch(u, json={"kind": "kev_added"}, headers=admin)
        assert r.status_code == 422
        assert (await c.get(u, headers=admin)).json()["kind"] == "cvss_min"
        assert (await c.patch(u, json={"recipients": []}, headers=admin)).status_code == 422


async def test_patch_keyword_rule_merged(ctx):
    app, admin, *_ = ctx
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", headers=admin, json=email_rule(
            kind="keyword", keyword="log4j"))).json()["id"]
        u = f"/api/alerts/rules/{rid}"
        r = await c.patch(u, json={"keyword": " spring "}, headers=admin)
        assert r.json()["keyword"] == "spring"
        assert (await c.patch(u, json={"keyword": None}, headers=admin)).status_code == 422
        assert (await c.patch(u, json={"threshold": 1}, headers=admin)).status_code == 422


async def test_delete_rule_cascades(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", json=hook_rule(), headers=admin)).json()["id"]
        assert db.scalars(select(AlertRecipient)).first() is not None
        r = await c.delete(f"/api/alerts/rules/{rid}", headers=admin)
        assert r.status_code == 204 and r.content == b""
        db.expire_all()
        assert db.scalars(select(AlertRecipient)).first() is None
        assert db.scalars(select(AlertRule)).first() is None
        assert (await c.get(f"/api/alerts/rules/{rid}", headers=admin)).status_code == 404


async def test_dns_flip_during_create_leaves_nothing(ctx, monkeypatch):
    app, admin, member, db = ctx
    calls = {"n": 0}

    def flip(host, port, *a, **k):
        calls["n"] += 1
        ip = PUBLIC_IP if calls["n"] <= 3 else "10.0.0.7"
        return [(socket.AF_INET, 0, 0, "", (ip, port))]

    monkeypatch.setattr(webhook.socket, "getaddrinfo", flip)
    body = hook_rule()
    body["recipients"] = body["recipients"] * 4  # 4th resolution is private
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", json=body, headers=admin)
    assert r.status_code == 422 and r.json() == {"error": "unsafe_webhook_url"}
    assert calls["n"] == 4  # one resolution per URL, no re-validation
    assert db.scalars(select(AlertRule)).first() is None
    assert db.scalars(select(AlertRecipient)).first() is None


async def test_create_resolves_each_url_once(ctx, monkeypatch):
    app, admin, *_ = ctx
    calls = {"n": 0}

    def count(host, port, *a, **k):
        calls["n"] += 1
        return [(socket.AF_INET, 0, 0, "", (PUBLIC_IP, port))]

    monkeypatch.setattr(webhook.socket, "getaddrinfo", count)
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", json=hook_rule(), headers=admin)
    assert r.status_code == 201 and calls["n"] == 1


async def test_webhook_url_encrypted_at_rest(ctx):
    app, admin, member, db = ctx
    async with client(app) as c:
        r = await c.post("/api/alerts/rules", json=hook_rule(), headers=admin)
        row = db.scalars(select(AlertRecipient)).one()
        assert row.webhook_url.startswith("v1:")
        assert "hooks.example.com" not in row.webhook_url
        assert "XXXSECRETPATH" not in row.webhook_url
        assert secretbox.decrypt(row.webhook_url).decode() == URL
        rid = r.json()["id"]
        add = await c.post(f"/api/alerts/rules/{rid}/recipients", headers=admin,
                           json={"channel": "webhook", "url": URL})
        assert add.status_code == 201
        for frag in ("XXXSECRETPATH", "querysecret", "T000", "/services"):
            assert frag not in add.text
        assert add.json()["url_masked"] == "https://hooks.example.com/\u2026"


async def test_undecryptable_url_masks_without_500(ctx, monkeypatch):
    app, admin, member, db = ctx
    async with client(app) as c:
        rid = (await c.post("/api/alerts/rules", json=hook_rule(), headers=admin)).json()["id"]
        monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
        get_settings.cache_clear()
        r = await c.get(f"/api/alerts/rules/{rid}", headers=admin)
        assert r.status_code == 200
        assert r.json()["recipients"][0]["url_masked"] == "https://(unavailable)/\u2026"
        assert (await c.get("/api/alerts/rules", headers=admin)).status_code == 200


async def test_control_chars_in_name_422(ctx):
    app, admin, *_ = ctx
    async with client(app) as c:
        for bad in (chr(0).join("ab"), "a"+chr(10)+"b", "a"+chr(127)+"b"):
            r = await c.post("/api/alerts/rules", json=email_rule(name=bad), headers=admin)
            assert r.status_code == 422
        rid = (await c.post("/api/alerts/rules", json=email_rule(), headers=admin)).json()["id"]
        r = await c.patch(f"/api/alerts/rules/{rid}", json={"name": chr(0).join("ab")}, headers=admin)
        assert r.status_code == 422
