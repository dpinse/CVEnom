import base64
import json
import os
import threading
import warnings
from contextlib import contextmanager
from datetime import UTC, datetime

import fakeredis
import pytest
from starlette.websockets import WebSocketDisconnect

from cvenom import live
from cvenom.api import create_app
from cvenom.api import routes_ws
from cvenom.auth.tokens import create_session, issue_access
from cvenom.collectors.base import CollectorResult
from cvenom.config import get_settings
from cvenom.models import User

with warnings.catch_warnings():  # starlette's TestClient warns about httpx at import time
    warnings.simplefilter("ignore")
    from starlette.testclient import TestClient


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def server():
    return fakeredis.FakeServer()


def make_app(db_session, server, **overrides):
    settings = get_settings().model_copy(update=overrides)

    @contextmanager
    def factory():
        yield db_session

    return create_app(settings, redis=fakeredis.FakeAsyncRedis(server=server), session_factory=factory)


def token_for(db_session, email="ws@example.com"):
    u = User(email=email, password_hash="x", role="member", is_active=True)
    db_session.add(u)
    db_session.flush()
    now = datetime.now(UTC)
    row, _ = create_session(db_session, u, now, "ua", "1.1.1.1")
    return issue_access(db_session, u, row.id, now), row


class Pumper:
    """Publish repeatedly until stopped: the subscribe inside the app races the test."""

    def __init__(self, server, payload):
        self.r = fakeredis.FakeRedis(server=server)
        self.payload = payload
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            self.r.publish(live.CHANNEL, self.payload)
            self.stop.wait(0.05)

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.t.join()


UPDATED = json.dumps({"type": "updated", "what": ["lanes"], "at": "2026-01-01T00:00:00+00:00"})


def expect_close(client, code, path="/api/ws/live", headers=None, send=None):
    with pytest.raises(WebSocketDisconnect) as ei:
        with client.websocket_connect(path, headers=headers or {}) as ws:
            if send is not None:
                ws.send_text(send)
            ws.receive_text()
    assert ei.value.code == code


def test_published_message_reaches_client(db_session, server):
    with TestClient(make_app(db_session, server)) as c:
        with c.websocket_connect("/api/ws/live") as ws:
            with Pumper(server, UPDATED):
                assert json.loads(ws.receive_text())["type"] == "updated"


def test_non_updated_message_not_forwarded(db_session, server):
    with TestClient(make_app(db_session, server)) as c:
        with c.websocket_connect("/api/ws/live") as ws:
            with Pumper(server, json.dumps({"type": "other"})):
                with Pumper(server, "not json"):
                    with Pumper(server, UPDATED):
                        # Every non-updated message is dropped; the first frame is an update.
                        assert json.loads(ws.receive_text())["type"] == "updated"


def test_ping_sent(db_session, server, monkeypatch):
    monkeypatch.setattr(routes_ws, "WS_PING_S", 0.1)
    with TestClient(make_app(db_session, server)) as c:
        with c.websocket_connect("/api/ws/live") as ws:
            assert json.loads(ws.receive_text()) == {"type": "ping"}


def test_client_messages_ignored(db_session, server):
    with TestClient(make_app(db_session, server)) as c:
        with c.websocket_connect("/api/ws/live") as ws:
            ws.send_text("x" * 5000)
            ws.send_text("hi")
            with Pumper(server, UPDATED):
                assert json.loads(ws.receive_text())["type"] == "updated"


def test_sixth_connection_closed_4429_and_slot_released(db_session, server):
    with TestClient(make_app(db_session, server)) as c:
        with contextlib_stack(c, 5):
            expect_close(c, 4429)
        # all five released: a new connection is accepted
        with c.websocket_connect("/api/ws/live"):
            pass
    r = fakeredis.FakeRedis(server=server)
    assert r.zcard("cvenom:ws:ip:testclient") == 0


@contextmanager
def contextlib_stack(client, n):
    from contextlib import ExitStack

    with ExitStack() as st:
        for _ in range(n):
            st.enter_context(client.websocket_connect("/api/ws/live"))
        yield


def test_redis_error_fails_open(db_session, server, monkeypatch):
    app = make_app(db_session, server)

    async def boom(*a, **k):
        raise ConnectionError("down")

    monkeypatch.setattr(app.state.redis, "eval", boom)
    with TestClient(app) as c:
        with c.websocket_connect("/api/ws/live"):
            pass


def test_no_auth_message_4401(db_session, server, monkeypatch):
    monkeypatch.setattr(routes_ws, "WS_AUTH_TIMEOUT_S", 0.2)
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        expect_close(c, 4401)


def test_invalid_token_4401(db_session, server):
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        expect_close(c, 4401, send=json.dumps({"type": "auth", "token": "garbage"}))


@pytest.mark.parametrize("msg", ["not json", "[]", '{"type":"auth"}', '{"type":"nope","token":"x"}', "x" * 5000])
def test_bad_auth_shape_4401(db_session, server, msg):
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        expect_close(c, 4401, send=msg)


def test_revoked_session_4401(db_session, server):
    token, row = token_for(db_session)
    row.revoked_at = datetime.now(UTC)
    db_session.flush()
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        expect_close(c, 4401, send=json.dumps({"type": "auth", "token": token}))


def test_valid_token_receives_updates(db_session, server):
    token, _ = token_for(db_session)
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        with c.websocket_connect("/api/ws/live") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": token}))
            with Pumper(server, UPDATED):
                assert json.loads(ws.receive_text())["type"] == "updated"


def test_query_token_ignored(db_session, server, monkeypatch):
    monkeypatch.setattr(routes_ws, "WS_AUTH_TIMEOUT_S", 0.2)
    token, _ = token_for(db_session)
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        expect_close(c, 4401, path=f"/api/ws/live?token={token}")


def test_token_expiry_closes_4401(db_session, server, monkeypatch):
    monkeypatch.setattr(routes_ws, "_seconds_until", lambda exp: 0.2)
    token, _ = token_for(db_session)
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        with pytest.raises(WebSocketDisconnect) as ei:
            with c.websocket_connect("/api/ws/live") as ws:
                ws.send_text(json.dumps({"type": "auth", "token": token}))
                ws.receive_text()
        assert ei.value.code == 4401


def test_deactivated_user_4401(db_session, server):
    token, _ = token_for(db_session)
    db_session.query(User).filter_by(email="ws@example.com").update({"is_active": False})
    db_session.flush()
    with TestClient(make_app(db_session, server, public_read=False)) as c:
        expect_close(c, 4401, send=json.dumps({"type": "auth", "token": token}))


def test_ip_bucket_is_zset_with_ttl_and_never_negative(db_session, server):
    r = fakeredis.FakeRedis(server=server)
    with TestClient(make_app(db_session, server)) as c:
        with contextlib_stack(c, 2):
            assert r.zcard("cvenom:ws:ip:testclient") == 2
            assert 0 < r.ttl("cvenom:ws:ip:testclient") <= 2 * routes_ws.WS_PING_S + 60
        assert r.zcard("cvenom:ws:ip:testclient") == 0
        assert r.type("cvenom:ws:ip:testclient") in (b"none", b"zset")


def test_stale_members_pruned_so_new_socket_allowed(db_session, server, monkeypatch):
    r = fakeredis.FakeRedis(server=server)
    key = "cvenom:ws:ip:testclient"
    clock = [1_000_000.0]
    monkeypatch.setattr(routes_ws, "_now", lambda: clock[0])
    for i in range(5):  # five fresh sockets that never heartbeat again (killed worker)
        r.zadd(key, {f"dead{i}": clock[0]})
    with TestClient(make_app(db_session, server)) as c:
        expect_close(c, 4429)  # still fresh: full
        clock[0] += 2 * routes_ws.WS_PING_S + 10  # heartbeats are now stale
        with c.websocket_connect("/api/ws/live"):
            assert r.zcard(key) == 1  # stale members gone


def test_global_cap_4429(db_session, server, monkeypatch):
    monkeypatch.setattr(routes_ws, "WS_MAX_TOTAL", 2)
    with TestClient(make_app(db_session, server)) as c:
        with contextlib_stack(c, 2):
            expect_close(c, 4429)
        with c.websocket_connect("/api/ws/live"):  # slots released
            pass


def test_single_subscriber_serves_many_sockets(db_session, server):
    app = make_app(db_session, server)
    created = []
    orig = app.state.redis.pubsub

    def counting(*a, **k):
        ps = orig(*a, **k)
        created.append(ps)
        return ps

    app.state.redis.pubsub = counting
    with TestClient(app) as c:
        with contextlib_stack(c, 3):
            pass
    # open all three, then check before closing
    created.clear()
    with TestClient(app) as c:
        from contextlib import ExitStack

        with ExitStack() as st:
            wss = [st.enter_context(c.websocket_connect("/api/ws/live")) for _ in range(3)]
            with Pumper(server, UPDATED):
                for ws in wss:
                    assert json.loads(ws.receive_text())["type"] == "updated"
            assert len(created) == 1


def test_slow_consumer_does_not_block_others():
    import asyncio

    hub = routes_ws.Hub()
    slow = asyncio.Queue(maxsize=routes_ws.WS_QUEUE_MAX)
    fast = asyncio.Queue(maxsize=routes_ws.WS_QUEUE_MAX)
    hub.queues.update({slow, fast})
    for i in range(routes_ws.WS_QUEUE_MAX):
        slow.put_nowait(f"old{i}")
    hub.fan_out("new")  # must not raise or block
    assert fast.get_nowait() == "new"
    assert slow.qsize() == routes_ws.WS_QUEUE_MAX and slow.get_nowait() == "old0"


def test_ipv6_same_64_shares_bucket():
    assert routes_ws._bucket("2001:db8:1:2::1") == routes_ws._bucket("2001:db8:1:2:ffff::9")
    assert routes_ws._bucket("2001:db8:1:2::1") != routes_ws._bucket("2001:db8:1:3::1")
    assert routes_ws._bucket("1.2.3.4") == "1.2.3.4"


def test_ipv6_same_64_limit_enforced_across_addresses(db_session, server):
    app = make_app(db_session, server)
    with TestClient(app, client=("2001:db8:1:2::1", 1)) as c1, TestClient(
        app, client=("2001:db8:1:2::2", 1)
    ) as c2:
        with contextlib_stack(c1, 5):
            expect_close(c2, 4429)


def test_disallowed_origin_4403(db_session, server):
    app = make_app(db_session, server, cors_origins=["https://app.example.com"])
    with TestClient(app) as c:
        expect_close(c, 4403, headers={"origin": "https://evil.example.com"})


def test_allowed_origin_and_no_origin_connect(db_session, server):
    app = make_app(db_session, server, cors_origins=["https://app.example.com"])
    with TestClient(app) as c:
        with c.websocket_connect("/api/ws/live", headers={"origin": "https://app.example.com"}):
            pass
        with c.websocket_connect("/api/ws/live"):  # non-browser client
            pass


def test_origin_not_checked_without_cors_origins(db_session, server):
    with TestClient(make_app(db_session, server, cors_origins=[])) as c:
        with c.websocket_connect("/api/ws/live", headers={"origin": "https://x.example.com"}):
            pass


# ---- live.py and run_collector -------------------------------------------------


def test_publish_exact_shape():
    r = fakeredis.FakeRedis()
    sub = r.pubsub()
    sub.subscribe(live.CHANNEL)
    sub.get_message(timeout=1)
    live.publish(r, ["lanes", "geo", "lanes"], now=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC))
    msg = sub.get_message(timeout=1)
    assert json.loads(msg["data"]) == {
        "type": "updated",
        "what": ["geo", "lanes"],
        "at": "2026-01-02T03:04:05+00:00",
    }


def test_what_changed_mapping():
    from cvenom.schemas import NormalizedCve

    assert live.what_changed(CollectorResult()) == []
    assert live.what_changed(CollectorResult(cves=[NormalizedCve(cve_id="CVE-2099-0001")])) == ["lanes"]
    assert live.what_changed(CollectorResult(stories=[object()])) == ["lanes", "stories"]
    assert live.what_changed(CollectorResult(geo_events=[object()])) == ["geo"]


# ----------------------------------------------- M-c / M-l (final review)


def test_total_released_when_setup_raises(db_session, server, monkeypatch):
    def boom(_conn):
        raise RuntimeError("client_ip failed")

    monkeypatch.setattr(routes_ws, "client_ip", boom)
    app = make_app(db_session, server)
    with TestClient(app) as c:
        with pytest.raises(Exception):
            with c.websocket_connect("/api/ws/live") as ws:
                ws.receive_text()
    assert routes_ws._hub(app).total == 0


def test_relayed_message_is_reserialized_and_filtered(db_session, server):
    noisy = json.dumps({"type": "updated", "what": ["lanes", "evil", 7, "geo"],
                        "x": "<script>", "at": "2026-01-01T00:00:00+00:00"})
    with TestClient(make_app(db_session, server)) as c:
        with c.websocket_connect("/api/ws/live") as ws:
            with Pumper(server, noisy):
                raw = ws.receive_text()
    assert json.loads(raw) == {"type": "updated", "what": ["lanes", "geo"]}


def test_relayed_message_with_no_known_what_is_dropped(db_session, server):
    with TestClient(make_app(db_session, server)) as c:
        with c.websocket_connect("/api/ws/live") as ws:
            with Pumper(server, json.dumps({"type": "updated", "what": ["evil"]})):
                with Pumper(server, json.dumps({"type": "updated", "what": "lanes"})):
                    with Pumper(server, UPDATED):
                        assert json.loads(ws.receive_text()) == {"type": "updated", "what": ["lanes"]}
