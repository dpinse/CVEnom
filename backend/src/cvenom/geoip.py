"""Local IP geolocation backed by MaxMind-format (mmdb) databases."""

from __future__ import annotations

import base64
import gzip
import io
import ipaddress
import logging
import os
import re
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import maxminddb

from cvenom.collectors.base import http_get_bytes
from cvenom.config import Settings

log = logging.getLogger(__name__)

COUNTRY_FILE = "country.mmdb"
ASN_FILE = "asn.mmdb"
_CC_RE = re.compile(r"^[A-Z]{2}$")
_MAX_DB_BYTES = 100_000_000

DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
MAXMIND_URL = "https://download.maxmind.com/geoip/databases/{edition}/download"


@dataclass(frozen=True)
class GeoResult:
    country_code: str | None
    asn: int | None


class GeoIP:
    def __init__(self, country, asn=None) -> None:
        self._country = country
        self._asn = asn

    @classmethod
    def open(cls, dir) -> GeoIP | None:
        """Open the databases in dir, fully loaded in memory (no file handles are held).

        Readers are a snapshot: re-open after refresh_geoip to pick up new data.
        Returns None if the country DB is missing or unusable.
        """
        d = Path(dir)
        cpath = d / COUNTRY_FILE
        if not cpath.is_file():
            return None
        try:
            country = maxminddb.open_database(str(cpath), maxminddb.MODE_MEMORY)
        except (OSError, ValueError, maxminddb.InvalidDatabaseError):
            log.warning("country database unusable; geolocation disabled")
            return None
        apath = d / ASN_FILE
        asn = None
        if apath.is_file():
            try:
                asn = maxminddb.open_database(str(apath), maxminddb.MODE_MEMORY)
            except (OSError, ValueError, maxminddb.InvalidDatabaseError):
                log.warning("ASN database unusable; continuing without ASN")
        return cls(country, asn)

    def lookup(self, ip: str) -> GeoResult | None:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if not addr.is_global:
            return None
        cc: str | None = None
        asn: int | None = None
        try:
            rec = self._country.get(str(addr))
            if isinstance(rec, dict):
                code = (rec.get("country") or {}).get("iso_code")
                if isinstance(code, str):
                    code = code.upper()
                    cc = code if _CC_RE.match(code) else None
            if self._asn is not None:
                arec = self._asn.get(str(addr))
                if isinstance(arec, dict):
                    n = arec.get("autonomous_system_number")
                    asn = n if isinstance(n, int) else None
        except (ValueError, maxminddb.InvalidDatabaseError):
            return None
        if cc is None and asn is None:
            return None
        return GeoResult(cc, asn)

    def close(self) -> None:
        self._country.close()
        if self._asn is not None:
            self._asn.close()


def _gunzip(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
        out = f.read(_MAX_DB_BYTES + 1)
    if len(out) > _MAX_DB_BYTES:
        raise ValueError("decompressed database exceeds size cap")
    return out


def _extract_mmdb(data: bytes) -> bytes:
    """Return the .mmdb member of a tar.gz, rejecting unsafe archives (no extractall)."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        found: bytes | None = None
        for m in tf:
            name = m.name.replace("\\", "/")
            parts = name.split("/")
            if name.startswith("/") or ".." in parts or re.match(r"^[A-Za-z]:", name):
                raise ValueError(f"unsafe path in archive: {m.name!r}")
            if found is None and m.isreg() and name.endswith(".mmdb"):
                if m.size > _MAX_DB_BYTES:
                    raise ValueError("database member exceeds size cap")
                f = tf.extractfile(m)
                if f is not None:
                    found = f.read()
        if found is None:
            raise ValueError("no .mmdb member in archive")
        return found


def _stage(directory: Path, payload: bytes, expect: str) -> Path:
    """Write payload to a temp file beside the target and verify it opens as an mmdb."""
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".geoip-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        reader = maxminddb.open_database(tmp, maxminddb.MODE_MEMORY)
        try:
            dbtype = reader.metadata().database_type
        finally:
            reader.close()
        if expect not in dbtype:
            raise ValueError(f"unexpected database type {dbtype!r}, wanted {expect!r}")
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return Path(tmp)


async def _fetch_dbip(kind: str, now: datetime) -> bytes:
    this = now.strftime("%Y-%m")
    prev = (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    try:
        raw = await http_get_bytes(
            DBIP_URL.format(kind=kind, month=this), follow_redirects=True
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            raise
        raw = await http_get_bytes(
            DBIP_URL.format(kind=kind, month=prev), follow_redirects=True
        )
    return _gunzip(raw)


async def _fetch_maxmind(edition: str, account: str, key: str) -> bytes:
    token = base64.b64encode(f"{account}:{key}".encode()).decode()
    raw = await http_get_bytes(
        MAXMIND_URL.format(edition=edition),
        params={"suffix": "tar.gz"},
        headers={"Authorization": f"Basic {token}"},
        follow_redirects=True,
    )
    return _extract_mmdb(raw)


async def refresh_geoip(dir, settings: Settings, *, now: datetime | None = None) -> str:
    """Download fresh databases into dir. Existing files are replaced only on full success."""
    now = now or datetime.now(UTC)
    directory = Path(dir)
    directory.mkdir(parents=True, exist_ok=True)

    account = settings.maxmind_account_id
    secret = settings.maxmind_license_key
    key = secret.get_secret_value() if secret else None
    if bool(account) != bool(key):
        log.warning("only one MaxMind credential is set; MaxMind not configured, using DB-IP")
    if account and key:
        provider = "maxmind"
        country = await _fetch_maxmind("GeoLite2-Country", account, key)
        asn = await _fetch_maxmind("GeoLite2-ASN", account, key)
    else:
        provider = "dbip"
        country = await _fetch_dbip("country", now)
        asn = await _fetch_dbip("asn", now)

    staged: list[tuple[Path, str]] = []
    try:
        staged.append((_stage(directory, country, "Country"), COUNTRY_FILE))
        staged.append((_stage(directory, asn, "ASN"), ASN_FILE))
        for tmp, final in staged:
            os.replace(tmp, directory / final)
        staged.clear()
    finally:
        for tmp, _ in staged:
            tmp.unlink(missing_ok=True)
    log.info("geoip databases refreshed from %s", provider)
    return provider
