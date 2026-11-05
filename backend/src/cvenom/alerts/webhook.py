"""Webhook sink helpers: SSRF-safe URL validation (pinning/sending added later)."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

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
