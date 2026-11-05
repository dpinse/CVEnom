import base64
import hashlib
import hmac
import json
import os
import socket
from datetime import date
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from cvenom import secretbox
from cvenom.alerts import webhook
from cvenom.alerts.email import EmailSink
from cvenom.alerts.sinks import SinkError, SinkNotConfigured, build_sinks
from cvenom.alerts.webhook import WebhookSink
from cvenom.models import AlertRecipient, AlertRule, Cve

SECRET = "s3cr3t-signing-key"
PATH = "/hooks/ABCDEF/tok-xyz"
URL = f"https://hooks.example.com{PATH}?k=v"
PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def _secrets_key(monkeypatch):
    from cvenom.config import get_settings

    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def dns(monkeypatch, *addrs):
    def f(host, port, *a, **k):
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, 0, 0, "", (ip, port))
                for ip in addrs]

    monkeypatch.setattr(webhook.socket, "getaddrinfo", f)


def make_cve(**kw):
    kw.setdefault("cve_id", "CVE-2099-0001")
    kw.setdefault("cvss", 9.8)
    kw.setdefault("epss_percentile", 0.97)
    kw.setdefault("kev_source", "cisa")
    kw.setdefault("kev_added", date(2026, 6, 1))
    kw.setdefault("summary", "a &lt;b&gt; &amp; c")
    return Cve(**kw)


def make_rule(name="rule one"):
    return AlertRule(id=7, name=name, kind="kev_added")


def hook_recipient(url=URL, secret=SECRET):
    return AlertRecipient(
        channel="webhook",
        webhook_url=secretbox.encrypt(url.encode()),
        webhook_secret_enc=secretbox.encrypt(secret.encode()),
    )


class Capture:
    def __init__(self, status=200, headers=None, content=b"ok"):
        self.requests = []
        self.status, self.headers, self.content = status, headers or {}, content

    def __call__(self, request):
        self.requests.append(request)
        return httpx.Response(self.status, headers=self.headers,
                              stream=httpx.ByteStream(self.content))


def sink_with(handler):
    return WebhookSink(transport=httpx.MockTransport(handler))


# ----------------------------------------------------------------- webhook


def test_webhook_pins_ip_and_keeps_host_and_sni(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    cap = Capture()
    sink_with(cap).send(None, make_cve(), make_rule(), hook_recipient())
    (req,) = cap.requests
    assert req.url.host == PUBLIC_IP
    assert req.url.scheme == "https"
    assert req.url.path == PATH and req.url.query == b"k=v"
    assert req.headers["host"] == "hooks.example.com"
    assert req.extensions["sni_hostname"] == "hooks.example.com"


def test_webhook_pins_ipv6_and_nondefault_port(monkeypatch):
    dns(monkeypatch, "2606:4700:4700::1111")
    cap = Capture()
    sink_with(cap).send(None, make_cve(), make_rule(),
                        hook_recipient("https://hooks.example.com:8443/x"))
    (req,) = cap.requests
    assert req.url.host == "2606:4700:4700::1111"
    assert req.url.port == 8443
    assert req.headers["host"] == "hooks.example.com:8443"
    assert req.extensions["sni_hostname"] == "hooks.example.com"


def test_webhook_dns_rebinding_refused_at_send(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    rec = hook_recipient()  # public when saved
    dns(monkeypatch, "10.0.0.5")  # private when sent
    cap = Capture()
    with pytest.raises(SinkError) as ei:
        sink_with(cap).send(None, make_cve(), make_rule(), rec)
    assert str(ei.value) == "webhook target rejected"
    assert cap.requests == []


def test_webhook_credentials_unavailable(monkeypatch):
    rec = AlertRecipient(channel="webhook", webhook_url="garbage", webhook_secret_enc="garbage")
    with pytest.raises(SinkError, match="^webhook credentials unavailable$"):
        sink_with(Capture()).send(None, make_cve(), make_rule(), rec)
    rec2 = AlertRecipient(channel="webhook")
    with pytest.raises(SinkError, match="^webhook credentials unavailable$"):
        sink_with(Capture()).send(None, make_cve(), make_rule(), rec2)


def test_webhook_redirect_not_followed(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    cap = Capture(status=302, headers={"location": "https://169.254.169.254/latest"})
    with pytest.raises(SinkError) as ei:
        sink_with(cap).send(None, make_cve(), make_rule(), hook_recipient())
    assert str(ei.value) == "webhook returned 302"
    assert len(cap.requests) == 1


@pytest.mark.parametrize("status", [400, 404, 500, 199])
def test_webhook_non_2xx_fails(monkeypatch, status):
    dns(monkeypatch, PUBLIC_IP)
    with pytest.raises(SinkError, match=f"^webhook returned {status}$"):
        sink_with(Capture(status=status)).send(None, make_cve(), make_rule(), hook_recipient())


def test_webhook_204_ok(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    sink_with(Capture(status=204, content=b"")).send(None, make_cve(), make_rule(), hook_recipient())


def test_webhook_signature_verifies_over_raw_body(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    cap = Capture()
    sink_with(cap).send(None, make_cve(), make_rule(), hook_recipient())
    req = cap.requests[0]
    body = req.content
    sig = req.headers["x-cvenom-signature"]
    t_part, v_part = sig.split(",")
    assert t_part.startswith("t=") and v_part.startswith("v1=")
    t = int(t_part[2:])
    expected = hmac.new(SECRET.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(v_part[3:], expected)
    assert req.headers["content-type"] == "application/json"
    assert req.headers["user-agent"] == "CVEnom/0.1 (+webhook)"
    assert b" " not in body.replace(b"rule one", b"").replace(b"a <b> & c", b"").replace(
        b"[CVEnom] CVE-2099-0001 exploited in the wild (CVSS 9.8)", b"")  # compact separators


def test_webhook_body_shape_mentions_and_unescape_once(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    cap = Capture()
    cve = make_cve(summary="&lt;x&gt; &amp;lt; " + "z" * 5000)
    sink_with(cap).send(None, cve, make_rule(), hook_recipient())
    data = json.loads(cap.requests[0].content)
    assert data["event"] == "kev_added" and data["cve_id"] == "CVE-2099-0001"
    assert data["rule"] == {"id": 7, "name": "rule one", "kind": "kev_added"}
    assert data["cve"]["cvss"] == 9.8 and data["cve"]["kev_source"] == "cisa"
    assert data["cve"]["kev_added"] == "2026-06-01"
    assert data["cve"]["summary"].startswith("<x> &lt; ")
    assert len(data["cve"]["summary"]) == 2000
    assert data["allowed_mentions"] == {"parse": []}
    assert data["content"] == data["text"] == "[CVEnom] CVE-2099-0001 exploited in the wild (CVSS 9.8)"
    assert data["sent_at"].endswith("+00:00")


def test_webhook_never_uses_event_payload(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    cap = Capture()
    sink_with(cap).send(SimpleNamespace(payload={"summary": "EVIL"}), make_cve(), make_rule(),
                        hook_recipient())
    assert b"EVIL" not in cap.requests[0].content


def test_webhook_response_read_is_capped(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    produced = {"n": 0}

    class Huge(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10 * 1024):  # 10 MB in 1 KB chunks
                produced["n"] += 1024
                yield b"x" * 1024

    def handler(request):
        return httpx.Response(200, stream=Huge())

    sink_with(handler).send(None, make_cve(), make_rule(), hook_recipient())
    assert produced["n"] <= 64 * 1024 + 8 * 1024


def test_webhook_transport_error_has_no_url_or_secret(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)

    def handler(request):
        raise httpx.ConnectError(f"boom {request.url} {SECRET}")

    with pytest.raises(SinkError) as ei:
        sink_with(handler).send(None, make_cve(), make_rule(), hook_recipient())
    msg = str(ei.value)
    assert msg == "webhook transport error: ConnectError"
    for needle in (PATH, "hooks.example.com", PUBLIC_IP, SECRET, "tok-xyz"):
        assert needle not in msg


def test_webhook_error_messages_leak_nothing(monkeypatch):
    dns(monkeypatch, "10.0.0.5")
    with pytest.raises(SinkError) as ei:
        sink_with(Capture()).send(None, make_cve(), make_rule(), hook_recipient())
    for needle in (PATH, "hooks.example.com", "10.0.0.5", SECRET):
        assert needle not in str(ei.value)


# ----------------------------------------------------------------- email


def smtp_settings(**kw):
    base = dict(smtp_host="mail.example.com", smtp_port=587, smtp_username="u",
                smtp_password=SecretStr("pw"), smtp_from_addr="cvenom@example.com",
                smtp_starttls=True)
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def smtp(monkeypatch):
    calls = []

    async def fake_send(message, **kw):
        calls.append((message, kw))

    monkeypatch.setattr("aiosmtplib.send", fake_send)
    return calls


def mail_recipient(email="dest@example.com"):
    return AlertRecipient(channel="email", email=email)


def test_email_message_content(smtp):
    EmailSink(smtp_settings()).send(None, make_cve(summary="&lt;b&gt; &amp;lt; " + "q" * 3000),
                                    make_rule(), mail_recipient())
    ((msg, kw),) = smtp
    assert msg["Subject"] == "[CVEnom] CVE-2099-0001 exploited in the wild"
    assert msg["From"] == "cvenom@example.com" and msg["To"] == "dest@example.com"
    assert msg.get_content_type() == "text/plain" and not msg.is_multipart()
    body = msg.get_content()
    assert "CVE-2099-0001" in body and "rule one" in body
    assert "9.8" in body and "0.97" in body and "cisa" in body and "2026-06-01" in body
    assert "<b> &lt; q" in body
    assert body.count("q") == 2000 - len("<b> &lt; ")
    assert "https://nvd.nist.gov/vuln/detail/CVE-2099-0001" in body
    assert kw["hostname"] == "mail.example.com" and kw["port"] == 587
    assert kw["start_tls"] is True and "use_tls" not in kw
    assert kw["username"] == "u" and kw["password"] == "pw" and kw["timeout"] == 15


def test_email_na_values(smtp):
    EmailSink(smtp_settings()).send(
        None, make_cve(cvss=None, epss_percentile=None, kev_source=None, kev_added=None),
        make_rule(), mail_recipient())
    body = smtp[0][0].get_content()
    assert "CVSS: n/a" in body and "EPSS percentile: n/a" in body


def test_email_subject_strips_crlf_and_truncates(smtp):
    cve = make_cve(cve_id="CVE-1\r\nBcc: evil@x.com\nX")
    EmailSink(smtp_settings()).send(None, cve, make_rule(name="r\r\nBcc: e@x"), mail_recipient())
    subj = smtp[0][0]["Subject"]
    assert "\r" not in subj and "\n" not in subj
    assert "Bcc" not in smtp[0][0].keys()
    smtp.clear()
    EmailSink(smtp_settings()).send(None, make_cve(cve_id="C" * 500), make_rule(), mail_recipient())
    assert len(smtp[0][0]["Subject"]) <= 200


def test_email_port_465_uses_implicit_tls(smtp):
    EmailSink(smtp_settings(smtp_port=465)).send(None, make_cve(), make_rule(), mail_recipient())
    kw = smtp[0][1]
    assert kw["use_tls"] is True and "start_tls" not in kw


def test_email_no_credentials_omitted(smtp):
    EmailSink(smtp_settings(smtp_username=None, smtp_password=None, smtp_starttls=False)).send(
        None, make_cve(), make_rule(), mail_recipient())
    kw = smtp[0][1]
    assert "username" not in kw and "password" not in kw and kw["start_tls"] is False


@pytest.mark.parametrize("over", [{"smtp_host": None}, {"smtp_from_addr": None}])
def test_email_not_configured(smtp, over):
    with pytest.raises(SinkNotConfigured, match="smtp not configured"):
        EmailSink(smtp_settings(**over)).send(None, make_cve(), make_rule(), mail_recipient())
    assert smtp == []


def test_email_recipient_without_address(smtp):
    with pytest.raises(SinkNotConfigured):
        EmailSink(smtp_settings()).send(None, make_cve(), make_rule(), mail_recipient(None))


def test_email_smtp_error_exposes_type_only(monkeypatch):
    class Boom(Exception):
        pass

    async def fake_send(message, **kw):
        raise Boom("535 auth failed for user u banner mail.example.com pw")

    monkeypatch.setattr("aiosmtplib.send", fake_send)
    with pytest.raises(SinkError) as ei:
        EmailSink(smtp_settings()).send(None, make_cve(), make_rule(), mail_recipient())
    assert str(ei.value) == "smtp error: Boom"


def test_build_sinks_registers_both():
    sinks = build_sinks()
    assert set(sinks) == {"email", "webhook"}
    assert isinstance(sinks["email"], EmailSink) and isinstance(sinks["webhook"], WebhookSink)


# ------------------------------------------ M-d: undecryptable credentials defer


def test_webhook_wrong_secrets_key_defers(monkeypatch):
    from cvenom.config import get_settings

    rec = hook_recipient()
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    cap = Capture()
    with pytest.raises(SinkNotConfigured, match="^webhook credentials unavailable$"):
        sink_with(cap).send(None, make_cve(), make_rule(), rec)
    assert cap.requests == []


def test_webhook_missing_secrets_key_defers(monkeypatch):
    from cvenom.config import get_settings

    rec = hook_recipient()
    monkeypatch.delenv("SECRETS_KEY")
    get_settings.cache_clear()
    with pytest.raises(SinkNotConfigured, match="^webhook credentials unavailable$"):
        sink_with(Capture()).send(None, make_cve(), make_rule(), rec)


def test_webhook_absent_credentials_are_a_hard_error():
    with pytest.raises(SinkError) as ei:
        sink_with(Capture()).send(None, make_cve(), make_rule(), AlertRecipient(channel="webhook"))
    assert not isinstance(ei.value, SinkNotConfigured)


# ------------------------------- M-a: 2xx then a broken/stalled body is success


class _BrokenBody(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"partial"
        raise httpx.ReadError("connection reset mid-body")


class _StalledBody(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"partial"
        import asyncio

        await asyncio.sleep(3600)
        yield b"never"


def test_webhook_2xx_with_broken_body_counts_as_success(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    sink_with(lambda req: httpx.Response(200, stream=_BrokenBody())).send(
        None, make_cve(), make_rule(), hook_recipient())


def test_webhook_2xx_with_stalled_body_counts_as_success(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    monkeypatch.setattr(webhook, "OVERALL_TIMEOUT_S", 0.2)
    sink_with(lambda req: httpx.Response(200, stream=_StalledBody())).send(
        None, make_cve(), make_rule(), hook_recipient())


def test_webhook_non_2xx_with_broken_body_reports_status(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    with pytest.raises(SinkError, match="^webhook returned 500$"):
        sink_with(lambda req: httpx.Response(500, stream=_BrokenBody())).send(
            None, make_cve(), make_rule(), hook_recipient())


def test_webhook_timeout_before_headers_is_failure(monkeypatch):
    dns(monkeypatch, PUBLIC_IP)
    monkeypatch.setattr(webhook, "OVERALL_TIMEOUT_S", 0.2)

    class SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            import asyncio

            await asyncio.sleep(3600)

    with pytest.raises(SinkError, match="^webhook transport error: TimeoutError$"):
        WebhookSink(transport=SlowTransport()).send(None, make_cve(), make_rule(), hook_recipient())


# ------------------------------------------- M-b: email timeout and recipients


def test_email_overall_timeout(monkeypatch):
    import asyncio

    from cvenom.alerts import email as email_mod

    async def slow(self, *a, **k):
        await asyncio.sleep(3600)

    monkeypatch.setattr(email_mod, "SEND_TIMEOUT_S", 0.2)
    monkeypatch.setattr(EmailSink, "_send", slow)
    with pytest.raises(SinkError) as ei:
        EmailSink(smtp_settings()).send(None, make_cve(), make_rule(), mail_recipient())
    assert str(ei.value) == "smtp error: TimeoutError"


def test_email_default_overall_timeout_is_30s():
    from cvenom.alerts import email as email_mod

    assert email_mod.SEND_TIMEOUT_S == 30


@pytest.mark.parametrize("addr", ["a@b.com, x@y.com", "a@b.com; x@y.com", "", "not-an-address"])
def test_email_multi_or_invalid_recipient_rejected(smtp, addr):
    with pytest.raises(SinkError) as ei:
        EmailSink(smtp_settings()).send(None, make_cve(), make_rule(), mail_recipient(addr or " "))
    assert str(ei.value) == "smtp error: invalid recipient"
    assert not isinstance(ei.value, SinkNotConfigured)
    assert smtp == []


def test_email_recipients_passed_explicitly(smtp):
    EmailSink(smtp_settings()).send(None, make_cve(), make_rule(), mail_recipient())
    assert smtp[0][1]["recipients"] == ["dest@example.com"]
