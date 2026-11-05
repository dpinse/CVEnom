import socket

import pytest

from cvenom.alerts import webhook
from cvenom.alerts.webhook import UnsafeWebhookURL, validate_url


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("unexpected DNS lookup")

    monkeypatch.setattr(webhook.socket, "getaddrinfo", boom)


def fake_dns(monkeypatch, *addrs):
    def f(host, port, *a, **k):
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, 0, 0, "", (ip, port))
            for ip in addrs
        ]

    monkeypatch.setattr(webhook.socket, "getaddrinfo", f)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/h",
        "https://user:pw@example.com/h",
        "https://127.0.0.1/h",
        "https://[::1]/h",
        "https://169.254.169.254/latest",
        "https://10.0.0.5/h",
        "https://[::ffff:192.168.0.1]/h",
        "https://100.64.0.1/h",
        "https://0.0.0.0/h",
        "https://[::ffff:127.0.0.1]/",
        "https://[fe80::1%25eth0]/",
        "https://[fe80::1%eth0]/",
        "https://[fc00::1]/",
        "https://224.0.0.1/",
        "https://[ff02::1]/",
        "https://[2002:7f00:1::]/",  # 6to4 wrapping 127.0.0.1
        "https://example.com:0/",
        "https://example.com:70000/",
        "https:///path",
        "https://example.com/a b",
        "https://example.com/\x00",
        "https://example.com/" + "a" * 2100,
        "ftp://example.com/",
        "",
    ],
)
def test_rejects(url):
    with pytest.raises(UnsafeWebhookURL):
        validate_url(url)


def test_localhost_resolving_to_loopback(monkeypatch):
    fake_dns(monkeypatch, "127.0.0.1")
    with pytest.raises(UnsafeWebhookURL):
        validate_url("https://localhost/")


def test_mixed_dns_rejected(monkeypatch):
    fake_dns(monkeypatch, "93.184.216.34", "10.1.2.3")
    with pytest.raises(UnsafeWebhookURL):
        validate_url("https://mixed.example/h")


def test_dns_failure_rejected(monkeypatch):
    def f(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(webhook.socket, "getaddrinfo", f)
    with pytest.raises(UnsafeWebhookURL):
        validate_url("https://nx.example/")


def test_empty_dns_rejected(monkeypatch):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", lambda *a, **k: [])
    with pytest.raises(UnsafeWebhookURL):
        validate_url("https://empty.example/")


def test_public_accepted_dedup_and_order(monkeypatch):
    fake_dns(monkeypatch, "93.184.216.34", "93.184.216.34", "2606:2800:220:1::1")
    t = validate_url("https://Example.COM./hook?a=1")
    assert t.host == "example.com" and t.port == 443
    assert t.ips == ("93.184.216.34", "2606:2800:220:1::1")


def test_explicit_port_and_public_literal():
    t = validate_url("https://93.184.216.34:8443/x")
    assert t.port == 8443 and t.ips == ("93.184.216.34",)


def test_idna_host(monkeypatch):
    fake_dns(monkeypatch, "93.184.216.34")
    t = validate_url("https://bücher.example/")
    assert t.host == "xn--bcher-kva.example"


def test_message_is_generic(monkeypatch):
    fake_dns(monkeypatch, "10.9.8.7")
    with pytest.raises(UnsafeWebhookURL) as e:
        validate_url("https://h.example/secret/path?token=abc")
    s = str(e.value)
    assert "10.9.8.7" not in s and "secret" not in s and "token" not in s


TRANSITION_FORMS = [
    "64:ff9b::7f00:1",  # NAT64 -> 127.0.0.1
    "64:ff9b::a9fe:a9fe",  # NAT64 -> 169.254.169.254
    "64:ff9b::a00:1",  # NAT64 -> 10.0.0.1
    "::7f00:1",  # IPv4-compatible
    "::127.0.0.1",
    "::ffff:0:7f00:1",  # IPv4-translated
    "64:ff9b:1::1",  # local-use NAT64
]


@pytest.mark.parametrize("ip", TRANSITION_FORMS)
def test_transition_forms_rejected_as_literal(ip):
    with pytest.raises(UnsafeWebhookURL):
        validate_url(f"https://[{ip}]/")


@pytest.mark.parametrize("ip", TRANSITION_FORMS)
def test_transition_forms_rejected_as_resolved(monkeypatch, ip):
    fake_dns(monkeypatch, ip)
    with pytest.raises(UnsafeWebhookURL):
        validate_url("https://t.example/")


def test_nat64_of_global_ipv4_accepted(monkeypatch):
    t = validate_url("https://[64:ff9b::808:808]/")
    assert t.ips == ("64:ff9b::808:808",)
    fake_dns(monkeypatch, "64:ff9b::808:808")
    assert validate_url("https://t.example/").ips == ("64:ff9b::808:808",)
