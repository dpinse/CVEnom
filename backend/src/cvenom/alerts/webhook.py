"""Webhook sink: SSRF-safe URL validation, IP pinning, HMAC-signed delivery."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from cvenom import secretbox
from cvenom.alerts.sinks import SinkError, SinkNotConfigured, clean_summary
from cvenom.models import AlertDelivery, AlertRecipient, AlertRule, Cve

MAX_URL_LEN = 2048
DEFAULT_PORT = 443


class UnsafeWebhookURL(Exception):
    """The webhook URL is malformed or targets a non-public address."""


@dataclass(frozen=True)
class ValidatedTarget:
    host: str
    port: int
    ips: tuple[str, ...]


_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "224.0.0.0/4",
        "ff00::/8",
        "::/96",  # IPv4-compatible
        "::ffff:0:0:0/96",  # IPv4-translated
        "64:ff9b:1::/48",  # local-use NAT64
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _unsafe() -> UnsafeWebhookURL:
    # Deliberately generic: never echo the URL, its path/query, or resolved IPs.
    return UnsafeWebhookURL("unsafe webhook url")


def _inner_addrs(ip: ipaddress._BaseAddress) -> list[ipaddress._BaseAddress]:
    out: list[ipaddress._BaseAddress] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            out.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            out.append(ip.sixtofour)
        if ip.teredo is not None:
            out.extend(ip.teredo)
        if ip in _NAT64:
            out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def _check_ip(ip: ipaddress._BaseAddress) -> None:
    for addr in _inner_addrs(ip):
        if not addr.is_global or addr.is_multicast:
            raise _unsafe()
        if any(addr.version == n.version and addr in n for n in _BLOCKED):
            raise _unsafe()


def _parse_ip(text: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def validate_url(url: str) -> ValidatedTarget:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
        raise _unsafe()
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F or ch == "\\" or ch.isspace() for ch in url):
        raise _unsafe()
    try:
        parts = urlsplit(url)
    except ValueError:
        raise _unsafe() from None
    if parts.scheme != "https":
        raise _unsafe()
    if "@" in parts.netloc:
        raise _unsafe()
    try:
        host = parts.hostname
        explicit_port = parts.port
    except ValueError:
        raise _unsafe() from None
    if not host:
        raise _unsafe()
    if "%" in host:  # IPv6 zone id (or stray escapes)
        raise _unsafe()
    host = host.rstrip(".").lower()
    if not host:
        raise _unsafe()
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise _unsafe() from None
    if explicit_port is None:
        port = DEFAULT_PORT
    elif 1 <= explicit_port <= 65535:
        port = explicit_port
    else:
        raise _unsafe()

    literal = _parse_ip(host)
    if literal is not None:
        _check_ip(literal)
        return ValidatedTarget(host=host, port=port, ips=(str(literal),))

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise _unsafe() from None
    ips: list[str] = []
    for info in infos:
        raw = str(info[4][0])
        if "%" in raw:
            raise _unsafe()
        ip = _parse_ip(raw)
        if ip is None:
            raise _unsafe()
        _check_ip(ip)
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise _unsafe()
    return ValidatedTarget(host=host, port=port, ips=tuple(ips))


MAX_RESPONSE_BYTES = 64 * 1024
OVERALL_TIMEOUT_S = 30


class _MissingCredential(Exception):
    pass


def _decrypt(token: str | None) -> str:
    if not token:
        raise _MissingCredential
    return secretbox.decrypt(token).decode()


def _build_body(cve: Cve, rule: AlertRule, now: datetime) -> bytes:
    cvss = "n/a" if cve.cvss is None else cve.cvss
    line = f"[CVEnom] {cve.cve_id} exploited in the wild (CVSS {cvss})"
    payload = {
        "event": "kev_added",
        "cve_id": cve.cve_id,
        "rule": {"id": rule.id, "name": rule.name, "kind": rule.kind},
        "cve": {
            "cve_id": cve.cve_id,
            "cvss": cve.cvss,
            "epss_percentile": cve.epss_percentile,
            "kev_source": cve.kev_source,
            "kev_added": cve.kev_added.isoformat() if cve.kev_added else None,
            "summary": clean_summary(cve.summary),
        },
        "sent_at": now.isoformat(),
        "content": line,  # Discord
        "text": line,  # Slack
        "allowed_mentions": {"parse": []},  # never ping @everyone from summary text
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


class WebhookSink:
    def __init__(self, settings=None, *, transport: httpx.AsyncBaseTransport | None = None):
        self._settings = settings
        self._transport = transport

    def send(self, delivery: AlertDelivery, cve: Cve, rule: AlertRule,
             recipient: AlertRecipient) -> None:
        try:
            url = _decrypt(recipient.webhook_url)
            secret = _decrypt(recipient.webhook_secret_enc)
        except (secretbox.SecretsKeyMissing, ValueError):
            # SECRETS_KEY missing or changed: defer (no attempt burned); the
            # dispatcher's 7-day expiry still bounds how long it stays pending.
            raise SinkNotConfigured("webhook credentials unavailable") from None
        except Exception:
            raise SinkError("webhook credentials unavailable") from None
        try:
            target = validate_url(url)  # re-validate now: defeats DNS rebinding
        except UnsafeWebhookURL:
            raise SinkError("webhook target rejected") from None
        now = datetime.now(timezone.utc)
        body = _build_body(cve, rule, now)
        status: list[int] = []  # set by _post as soon as the response headers arrive
        try:
            asyncio.run(asyncio.wait_for(
                self._post(url, target, secret, body, int(now.timestamp()), status),
                OVERALL_TIMEOUT_S))
        except SinkError:
            raise
        except Exception as exc:
            # The receiver already answered: a body that breaks or stalls (incl. the
            # overall timeout) must not turn a 2xx into a retry (= duplicate alert).
            if status:
                if 200 <= status[0] < 300:
                    return
                raise SinkError(f"webhook returned {status[0]}") from None
            # Never include str(exc): httpx messages embed the URL.
            raise SinkError(f"webhook transport error: {type(exc).__name__}") from None
        if not 200 <= status[0] < 300:
            raise SinkError(f"webhook returned {status[0]}")

    async def _post(self, url: str, target: ValidatedTarget, secret: str, body: bytes,
                    ts: int, status: list[int]) -> None:
        parts = urlsplit(url)
        ip = target.ips[0]
        ip_host = f"[{ip}]" if ":" in ip else ip
        pinned = f"https://{ip_host}:{target.port}{parts.path or '/'}"
        if parts.query:
            pinned += f"?{parts.query}"
        host_hdr = f"[{target.host}]" if ":" in target.host else target.host
        if target.port != DEFAULT_PORT:
            host_hdr += f":{target.port}"
        headers = {
            "Host": host_hdr,
            "Content-Type": "application/json",
            "User-Agent": "CVEnom/0.1 (+webhook)",
            "X-CVEnom-Signature": sign(secret, ts, body),
        }
        async with httpx.AsyncClient(follow_redirects=False, timeout=10, verify=True,
                                     transport=self._transport, trust_env=False) as client:
            async with client.stream("POST", pinned, content=body, headers=headers,
                                     extensions={"sni_hostname": target.host}) as resp:
                status.append(resp.status_code)
                read = 0
                async for chunk in resp.aiter_raw():  # drain (capped) so the conn closes cleanly
                    read += len(chunk)
                    if read >= MAX_RESPONSE_BYTES:
                        break
