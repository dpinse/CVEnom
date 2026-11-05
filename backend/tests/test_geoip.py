import base64
import gzip
import io
import logging
import tarfile
from datetime import datetime, timezone

import maxminddb
import pytest
import respx
from mmdb_writer import MMDBWriter
from netaddr import IPSet

from cvenom.config import Settings
from cvenom.geoip import GeoIP, GeoResult, refresh_geoip

KEY = "s3cr3t-license-key-xyz"


def _build(path, data: dict) -> bytes:
    w = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="Test")
    for net, rec in data.items():
        w.insert_network(IPSet([net]), rec)
    w.to_db_file(str(path))
    return path.read_bytes()


@pytest.fixture(scope="module")
def db_bytes(tmp_path_factory):
    d = tmp_path_factory.mktemp("fx")
    country = _build(
        d / "c.mmdb",
        {
            "8.8.8.0/24": {"country": {"iso_code": "us"}},
            "2001:4860::/32": {"country": {"iso_code": "DE"}},
            "9.9.9.0/24": {"country": {"iso_code": "USA"}},
        },
    )
    asn = _build(d / "a.mmdb", {"8.8.8.0/24": {"autonomous_system_number": 15169}})
    return country, asn


@pytest.fixture
def geo_dir(tmp_path, db_bytes):
    (tmp_path / "country.mmdb").write_bytes(db_bytes[0])
    (tmp_path / "asn.mmdb").write_bytes(db_bytes[1])
    return tmp_path


def settings(**kw) -> Settings:
    return Settings(database_url="x", redis_url="y", **kw)


def test_lookup_public(geo_dir):
    g = GeoIP.open(geo_dir)
    assert g.lookup("8.8.8.8") == GeoResult("US", 15169)
    assert g.lookup("2001:4860::1") == GeoResult("DE", None)
    g.close()


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "127.0.0.1",
        "::1",
        "169.254.1.1",
        "100.64.0.1",
        "not-an-ip",
        "::ffff:10.0.0.1",
        "1.2.3.4",
        "",
        "9.9.9.9",  # invalid country code, no ASN
    ],
)
def test_lookup_none(geo_dir, ip):
    assert GeoIP.open(geo_dir).lookup(ip) is None


def test_mapped_public_unwrapped(geo_dir):
    assert GeoIP.open(geo_dir).lookup("::ffff:8.8.8.8") == GeoResult("US", 15169)


def test_open_without_country_db(tmp_path):
    assert GeoIP.open(tmp_path) is None
    assert GeoIP.open(tmp_path / "missing") is None


def test_open_country_only(tmp_path, db_bytes):
    (tmp_path / "country.mmdb").write_bytes(db_bytes[0])
    assert GeoIP.open(tmp_path).lookup("8.8.8.8") == GeoResult("US", None)


NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
DBIP_C = "https://download.db-ip.com/free/dbip-country-lite-{}.mmdb.gz"
DBIP_A = "https://download.db-ip.com/free/dbip-asn-lite-{}.mmdb.gz"


@respx.mock
async def test_dbip_refresh(tmp_path, db_bytes):
    respx.get(DBIP_C.format("2026-11")).respond(200, content=gzip.compress(db_bytes[0]))
    respx.get(DBIP_A.format("2026-11")).respond(200, content=gzip.compress(db_bytes[1]))
    assert await refresh_geoip(tmp_path, settings(), now=NOW) == "dbip"
    assert (tmp_path / "country.mmdb").read_bytes() == db_bytes[0]
    assert (tmp_path / "asn.mmdb").read_bytes() == db_bytes[1]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["asn.mmdb", "country.mmdb"]
    assert GeoIP.open(tmp_path).lookup("8.8.8.8") == GeoResult("US", 15169)


@respx.mock
async def test_dbip_previous_month_fallback(tmp_path, db_bytes):
    respx.get(DBIP_C.format("2026-11")).respond(404)
    respx.get(DBIP_A.format("2026-11")).respond(404)
    respx.get(DBIP_C.format("2026-10")).respond(200, content=gzip.compress(db_bytes[0]))
    respx.get(DBIP_A.format("2026-10")).respond(200, content=gzip.compress(db_bytes[1]))
    assert await refresh_geoip(tmp_path, settings(), now=NOW) == "dbip"
    assert (tmp_path / "country.mmdb").read_bytes() == db_bytes[0]


@respx.mock
async def test_january_falls_back_to_december(tmp_path, db_bytes):
    jan = datetime(2026, 1, 3, tzinfo=timezone.utc)
    respx.get(DBIP_C.format("2026-01")).respond(404)
    respx.get(DBIP_A.format("2026-01")).respond(404)
    respx.get(DBIP_C.format("2025-12")).respond(200, content=gzip.compress(db_bytes[0]))
    respx.get(DBIP_A.format("2025-12")).respond(200, content=gzip.compress(db_bytes[1]))
    assert await refresh_geoip(tmp_path, settings(), now=jan) == "dbip"


@respx.mock
async def test_corrupt_download_leaves_existing(geo_dir, db_bytes):
    respx.get(DBIP_C.format("2026-11")).respond(200, content=gzip.compress(b"not a mmdb"))
    respx.get(DBIP_A.format("2026-11")).respond(200, content=gzip.compress(db_bytes[1]))
    before = (geo_dir / "country.mmdb").read_bytes()
    with pytest.raises((ValueError, maxminddb.InvalidDatabaseError)):
        await refresh_geoip(geo_dir, settings(), now=NOW)
    assert (geo_dir / "country.mmdb").read_bytes() == before
    assert sorted(p.name for p in geo_dir.iterdir()) == ["asn.mmdb", "country.mmdb"]


def _tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


MM_C = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download"
MM_A = "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download"


@respx.mock
async def test_maxmind_basic_auth(tmp_path, db_bytes, caplog):
    caplog.set_level(logging.DEBUG)
    rc = respx.get(MM_C).respond(
        200,
        content=_tar(
            {
                "GeoLite2-Country_20261103/GeoLite2-Country.mmdb": db_bytes[0],
                "GeoLite2-Country_20261103/README.txt": b"hi",
            }
        ),
    )
    ra = respx.get(MM_A).respond(
        200, content=_tar({"GeoLite2-ASN_20261103/GeoLite2-ASN.mmdb": db_bytes[1]})
    )
    s = settings(maxmind_account_id="12345", maxmind_license_key=KEY)
    assert await refresh_geoip(tmp_path, s, now=NOW) == "maxmind"
    expected = "Basic " + base64.b64encode(f"12345:{KEY}".encode()).decode()
    for r in (rc, ra):
        req = r.calls.last.request
        assert req.headers["Authorization"] == expected
        assert "license_key" not in str(req.url)
        assert KEY not in str(req.url)
        assert req.url.params.get("suffix") == "tar.gz"
    assert KEY not in caplog.text
    assert GeoIP.open(tmp_path).lookup("8.8.8.8") == GeoResult("US", 15169)


@respx.mock
async def test_maxmind_rejects_traversal(geo_dir, db_bytes):
    respx.get(MM_C).respond(200, content=_tar({"../evil.mmdb": db_bytes[0]}))
    respx.get(MM_A).respond(200, content=_tar({"x/GeoLite2-ASN.mmdb": db_bytes[1]}))
    before = (geo_dir / "country.mmdb").read_bytes()
    s = settings(maxmind_account_id="12345", maxmind_license_key=KEY)
    with pytest.raises(ValueError):
        await refresh_geoip(geo_dir, s, now=NOW)
    assert (geo_dir / "country.mmdb").read_bytes() == before
    assert not (geo_dir.parent / "evil.mmdb").exists()


@respx.mock
async def test_maxmind_rejects_absolute(geo_dir, db_bytes):
    respx.get(MM_C).respond(200, content=_tar({"/abs/c.mmdb": db_bytes[0]}))
    respx.get(MM_A).respond(200, content=_tar({"x/a.mmdb": db_bytes[1]}))
    s = settings(maxmind_account_id="12345", maxmind_license_key=KEY)
    with pytest.raises(ValueError):
        await refresh_geoip(geo_dir, s, now=NOW)
