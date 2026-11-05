import pytest
from pydantic import ValidationError

from cvenom.schemas import NormalizedCve

NAN = float("nan")
INF = float("inf")


@pytest.mark.parametrize("v", [10.5, -1, NAN, INF])
def test_cvss_rejects_invalid(v):
    with pytest.raises(ValidationError):
        NormalizedCve(cve_id="CVE-2026-1001", cvss=v)


@pytest.mark.parametrize("field", ["epss", "epss_percentile"])
@pytest.mark.parametrize("v", [1.5, -0.1, NAN, INF])
def test_epss_fields_reject_invalid(field, v):
    with pytest.raises(ValidationError):
        NormalizedCve(cve_id="CVE-2026-1001", **{field: v})


def test_none_and_boundaries_accepted():
    c = NormalizedCve(cve_id="CVE-2026-1001")
    assert c.cvss is None and c.epss is None and c.epss_percentile is None
    lo = NormalizedCve(cve_id="CVE-2026-1001", cvss=0, epss=0, epss_percentile=0)
    hi = NormalizedCve(cve_id="CVE-2026-1001", cvss=10, epss=1, epss_percentile=1)
    assert lo.cvss == 0 and hi.cvss == 10 and hi.epss == 1 and hi.epss_percentile == 1


@pytest.mark.parametrize(
    "raw, expected",
    [(" cve-2024-1234 ", "CVE-2024-1234"), ("CVE-2026-109618", "CVE-2026-109618"), ("CVE-2024-1234567", "CVE-2024-1234567")],
)
def test_cve_id_normalized(raw, expected):
    assert NormalizedCve(cve_id=raw).cve_id == expected


@pytest.mark.parametrize(
    "bad", ["CVE-1<img src=x>", "CVE-24-1", "", "CVE-2024-123", "CVE-2024-12345678", "CVE-2024-1234 x", "GHSA-aaaa-bbbb-cccc"]
)
def test_cve_id_rejects_invalid(bad):
    with pytest.raises(ValidationError):
        NormalizedCve(cve_id=bad)


def test_story_url_rejects_non_http_schemes():
    from datetime import datetime, timezone

    from cvenom.schemas import NormalizedStory

    now = datetime(2026, 11, 4, tzinfo=timezone.utc)
    for bad in ["javascript:alert(1)", "data:text/html,x", "ftp://x/y", "//evil", ""]:
        with pytest.raises(ValidationError):
            NormalizedStory(url=bad, source="s", title="t", summary="s", published=now)
    assert NormalizedStory(url=" https://x.org/a ", source="s", title="t", summary="s", published=now).url == "https://x.org/a"


def test_story_url_accepts_uppercase_scheme_rejects_whitespace_and_control():
    from datetime import datetime, timezone

    from cvenom.schemas import NormalizedStory

    now = datetime(2026, 11, 4, tzinfo=timezone.utc)
    ok = NormalizedStory(url="HTTPS://x.org/a", source="s", title="t", summary="s", published=now)
    assert ok.url == "HTTPS://x.org/a"
    for bad in ["https://x.org/a b", "https://x.org/a\nb", "https://x.org/\x00", "https://x.org/a\tb"]:
        with pytest.raises(ValidationError):
            NormalizedStory(url=bad, source="s", title="t", summary="s", published=now)


def test_geo_event_validates_country_and_magnitude():
    from datetime import datetime, timezone

    from cvenom.schemas import NormalizedGeoEvent

    now = datetime(2026, 11, 4, tzinfo=timezone.utc)
    ev = NormalizedGeoEvent(source="x", external_id="1", kind="scan", country_code="us", observed_at=now)
    assert ev.country_code == "US"
    for bad in [dict(country_code="USA"), dict(magnitude=float("nan")), dict(magnitude=-1), dict(kind="other")]:
        with pytest.raises(ValidationError):
            NormalizedGeoEvent(**{**dict(source="x", external_id="1", kind="scan", observed_at=now), **bad})


def test_geo_event_naive_observed_at_is_utc_and_others_normalized():
    from datetime import datetime, timedelta, timezone

    from cvenom.schemas import NormalizedGeoEvent

    base = dict(source="x", external_id="1", kind="scan")
    ev = NormalizedGeoEvent(**base, observed_at=datetime(2026, 11, 4, 12))
    assert ev.observed_at == datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
    assert ev.observed_at.utcoffset() == timedelta(0)
    tz = timezone(timedelta(hours=2))
    ev = NormalizedGeoEvent(**base, observed_at=datetime(2026, 11, 4, 12, tzinfo=tz))
    assert ev.observed_at.hour == 10 and ev.observed_at.utcoffset() == timedelta(0)
    assert ev.magnitude == 1.0 and ev.details == {} and ev.label is None


def test_geo_event_rejects_bad_cve_story_url_and_asn():
    from datetime import datetime, timezone

    from cvenom.schemas import NormalizedGeoEvent

    now = datetime(2026, 11, 4, tzinfo=timezone.utc)
    base = dict(source="x", external_id="1", kind="scan", observed_at=now)
    assert NormalizedGeoEvent(**base, cve_id=" cve-2024-1234 ").cve_id == "CVE-2024-1234"
    for bad in [dict(cve_id="CVE-bad"), dict(story_url="javascript:alert(1)"), dict(asn=-1)]:
        with pytest.raises(ValidationError):
            NormalizedGeoEvent(**{**base, **bad})


def _story(**kw):
    from datetime import datetime, timezone

    from cvenom.schemas import NormalizedStory

    base = dict(url="https://example.com/a", source="s", title="t", summary="x",
                published=datetime(2026, 11, 1, tzinfo=timezone.utc))
    return NormalizedStory(**{**base, **kw})


def _geo(**kw):
    from datetime import datetime, timezone

    from cvenom.schemas import NormalizedGeoEvent

    base = dict(source="x", external_id="1", kind="scan",
                observed_at=datetime(2026, 11, 1, tzinfo=timezone.utc))
    return NormalizedGeoEvent(**{**base, **kw})


@pytest.mark.parametrize("year", [1969, 2101])
def test_story_and_geo_reject_years_outside_1970_2100(year):
    from datetime import datetime, timezone

    dt = datetime(year, 6, 1, tzinfo=timezone.utc)
    with pytest.raises(ValidationError):
        _story(published=dt)
    with pytest.raises(ValidationError):
        _geo(observed_at=dt)


def test_future_dates_clamped_to_now_but_small_skew_kept():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    for make, field in ((_story, "published"), (_geo, "observed_at")):
        far = getattr(make(**{field: now + timedelta(days=1)}), field)
        assert abs(far - now) < timedelta(minutes=1)
        near = now + timedelta(minutes=30)
        assert getattr(make(**{field: near}), field) == near


@pytest.mark.parametrize("bad", ["a" * 257, "a\x00b", "   ", "", "a\x7fb", "a\nb"])
def test_geo_external_id_rejected(bad):
    with pytest.raises(ValidationError):
        _geo(external_id=bad)


def test_geo_external_id_256_ok_and_asn_bound():
    assert _geo(external_id="a" * 256).external_id == "a" * 256
    assert _geo(asn=2**32 - 1).asn == 2**32 - 1
    with pytest.raises(ValidationError):
        _geo(asn=2**32)


@pytest.mark.parametrize("bad", [
    "https://www.bleepingcomputer.com@evil.example/",
    "https://user:pw@host/",
    "https://user@host/",
])
def test_story_url_rejects_userinfo(bad):
    with pytest.raises(ValidationError):
        _story(url=bad)


def test_story_url_normal_urls_still_pass():
    for ok in ("https://www.bleepingcomputer.com/news/x?a=b@c", "http://host:8080/p"):
        assert _story(url=ok).url == ok
