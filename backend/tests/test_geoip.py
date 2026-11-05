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


def _build(path, data: dict, dbtype: str) -> bytes:
    w = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type=dbtype)
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
        "DBIP-Country-Lite",
    )
    asn = _build(
        d / "a.mmdb", {"8.8.8.0/24": {"autonomous_system_number": 15169}}, "DBIP-ASN-Lite"
    )
    return country, asn


@pytest.fixture
def geo_dir(tmp_path, db_bytes):
    (tmp_path / "country.mmdb").write_bytes(db_bytes[0])
    (tmp_path / "asn.mmdb").write_bytes(db_bytes[1])
    return tmp_path


def _lookup(d, ip):
    g = GeoIP.open(d)
    try:
        return g.lookup(ip)
    finally:
        g.close()


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
    assert _lookup(geo_dir, ip) is None


def test_mapped_public_unwrapped(geo_dir):
    assert _lookup(geo_dir, "::ffff:8.8.8.8") == GeoResult("US", 15169)


def test_open_without_country_db(tmp_path):
    assert GeoIP.open(tmp_path) is None
    assert GeoIP.open(tmp_path / "missing") is None


def test_open_country_only(tmp_path, db_bytes):
    (tmp_path / "country.mmdb").write_bytes(db_bytes[0])
    assert _lookup(tmp_path, "8.8.8.8") == GeoResult("US", None)


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
    assert _lookup(tmp_path, "8.8.8.8") == GeoResult("US", 15169)


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
    assert _lookup(tmp_path, "8.8.8.8") == GeoResult("US", 15169)


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


# ---- fix round 1 ----

MM_CDN = "https://storage.example-cdn.net/presigned/country.tar.gz"
MM_CDN_A = "https://storage.example-cdn.net/presigned/asn.tar.gz"


@respx.mock
async def test_maxmind_redirect_drops_auth(tmp_path, db_bytes):
    respx.get(MM_C).respond(302, headers={"Location": MM_CDN})
    respx.get(MM_A).respond(302, headers={"Location": MM_CDN_A})
    cdn_c = respx.get(MM_CDN).respond(200, content=_tar({"d/c.mmdb": db_bytes[0]}))
    cdn_a = respx.get(MM_CDN_A).respond(200, content=_tar({"d/a.mmdb": db_bytes[1]}))
    s = settings(maxmind_account_id="12345", maxmind_license_key=KEY)
    assert await refresh_geoip(tmp_path, s, now=NOW) == "maxmind"
    for r in (cdn_c, cdn_a):
        assert "authorization" not in r.calls.last.request.headers
    assert _lookup(tmp_path, "8.8.8.8") == GeoResult("US", 15169)


@respx.mock
async def test_dbip_follows_redirect(tmp_path, db_bytes):
    respx.get(DBIP_C.format("2026-11")).respond(302, headers={"Location": MM_CDN})
    respx.get(MM_CDN).respond(200, content=gzip.compress(db_bytes[0]))
    respx.get(DBIP_A.format("2026-11")).respond(200, content=gzip.compress(db_bytes[1]))
    assert await refresh_geoip(tmp_path, settings(), now=NOW) == "dbip"


def test_open_corrupt_asn_keeps_country_and_releases_files(geo_dir):
    (geo_dir / "asn.mmdb").write_bytes(b"garbage" * 10)
    g = GeoIP.open(geo_dir)
    assert g.lookup("8.8.8.8") == GeoResult("US", None)
    g.close()
    (geo_dir / "asn.mmdb").unlink()
    (geo_dir / "country.mmdb").unlink()


def test_open_corrupt_country_returns_none(geo_dir):
    (geo_dir / "country.mmdb").write_bytes(b"garbage" * 10)
    assert GeoIP.open(geo_dir) is None
    (geo_dir / "asn.mmdb").unlink()
    (geo_dir / "country.mmdb").unlink()


def test_open_holds_no_file_handle(geo_dir, db_bytes):
    g = GeoIP.open(geo_dir)
    (geo_dir / "tmp").write_bytes(db_bytes[0])
    import os

    os.replace(geo_dir / "tmp", geo_dir / "country.mmdb")  # would fail on Windows if mmapped
    assert g.lookup("8.8.8.8") == GeoResult("US", 15169)
    g.close()


def test_license_key_not_in_repr():
    s = settings(maxmind_account_id="1", maxmind_license_key=KEY)
    assert KEY not in repr(s)
    assert KEY not in str(s)


@respx.mock
async def test_wrong_database_type_rejected(geo_dir, db_bytes):
    # ASN db served in the country slot
    respx.get(DBIP_C.format("2026-11")).respond(200, content=gzip.compress(db_bytes[1]))
    respx.get(DBIP_A.format("2026-11")).respond(200, content=gzip.compress(db_bytes[1]))
    before = (geo_dir / "country.mmdb").read_bytes()
    with pytest.raises(ValueError):
        await refresh_geoip(geo_dir, settings(), now=NOW)
    assert (geo_dir / "country.mmdb").read_bytes() == before


@respx.mock
async def test_second_db_failure_keeps_first(geo_dir, db_bytes):
    respx.get(DBIP_C.format("2026-11")).respond(200, content=gzip.compress(db_bytes[0] + b""))
    respx.get(DBIP_A.format("2026-11")).respond(200, content=gzip.compress(b"junk"))
    (geo_dir / "country.mmdb").write_bytes(b"OLD")
    with pytest.raises(Exception):
        await refresh_geoip(geo_dir, settings(), now=NOW)
    assert (geo_dir / "country.mmdb").read_bytes() == b"OLD"
    assert sorted(p.name for p in geo_dir.iterdir()) == ["asn.mmdb", "country.mmdb"]


def _tar_special(kind: str, db: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        ti = tarfile.TarInfo("d/link.mmdb")
        ti.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
        ti.linkname = "/etc/passwd" if kind == "sym" else "d/real.mmdb"
        t.addfile(ti)
    return buf.getvalue()


@pytest.mark.parametrize("kind", ["sym", "hard"])
def test_links_never_read(kind, db_bytes):
    from cvenom.geoip import _extract_mmdb

    with pytest.raises(ValueError, match="no .mmdb"):
        _extract_mmdb(_tar_special(kind, db_bytes[0]))


def test_oversize_member_rejected(monkeypatch, db_bytes):
    from cvenom import geoip

    monkeypatch.setattr(geoip, "_MAX_DB_BYTES", 10)
    with pytest.raises(ValueError, match="size cap"):
        geoip._extract_mmdb(_tar({"d/c.mmdb": db_bytes[0]}))


def test_gunzip_over_cap_rejected(monkeypatch, db_bytes):
    from cvenom import geoip

    monkeypatch.setattr(geoip, "_MAX_DB_BYTES", 10)
    with pytest.raises(ValueError, match="size cap"):
        geoip._gunzip(gzip.compress(db_bytes[0]))


@respx.mock
async def test_single_maxmind_credential_warns_and_uses_dbip(tmp_path, db_bytes, caplog):
    caplog.set_level(logging.WARNING)
    respx.get(DBIP_C.format("2026-11")).respond(200, content=gzip.compress(db_bytes[0]))
    respx.get(DBIP_A.format("2026-11")).respond(200, content=gzip.compress(db_bytes[1]))
    assert await refresh_geoip(tmp_path, settings(maxmind_account_id="1"), now=NOW) == "dbip"
    assert "MaxMind not configured" in caplog.text
