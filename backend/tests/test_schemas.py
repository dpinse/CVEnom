from datetime import UTC

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
    from datetime import datetime

    from cvenom.schemas import NormalizedStory

    now = datetime(2026, 11, 4, tzinfo=UTC)
    for bad in ["javascript:alert(1)", "data:text/html,x", "ftp://x/y", "//evil", ""]:
        with pytest.raises(ValidationError):
            NormalizedStory(url=bad, source="s", title="t", summary="s", published=now)
    assert NormalizedStory(url=" https://x.org/a ", source="s", title="t", summary="s", published=now).url == "https://x.org/a"


def test_story_url_accepts_uppercase_scheme_rejects_whitespace_and_control():
    from datetime import datetime

    from cvenom.schemas import NormalizedStory

    now = datetime(2026, 11, 4, tzinfo=UTC)
    ok = NormalizedStory(url="HTTPS://x.org/a", source="s", title="t", summary="s", published=now)
    assert ok.url == "HTTPS://x.org/a"
    for bad in ["https://x.org/a b", "https://x.org/a\nb", "https://x.org/\x00", "https://x.org/a\tb"]:
        with pytest.raises(ValidationError):
            NormalizedStory(url=bad, source="s", title="t", summary="s", published=now)


def test_geo_event_validates_country_and_magnitude():
    from datetime import datetime

    from cvenom.schemas import NormalizedGeoEvent

    now = datetime(2026, 11, 4, tzinfo=UTC)
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
    assert ev.observed_at == datetime(2026, 11, 4, 12, tzinfo=UTC)
    assert ev.observed_at.utcoffset() == timedelta(0)
    tz = timezone(timedelta(hours=2))
    ev = NormalizedGeoEvent(**base, observed_at=datetime(2026, 11, 4, 12, tzinfo=tz))
    assert ev.observed_at.hour == 10 and ev.observed_at.utcoffset() == timedelta(0)
    assert ev.magnitude == 1.0 and ev.details == {} and ev.label is None


def test_geo_event_rejects_bad_cve_story_url_and_asn():
    from datetime import datetime

    from cvenom.schemas import NormalizedGeoEvent

    now = datetime(2026, 11, 4, tzinfo=UTC)
    base = dict(source="x", external_id="1", kind="scan", observed_at=now)
    assert NormalizedGeoEvent(**base, cve_id=" cve-2024-1234 ").cve_id == "CVE-2024-1234"
    for bad in [dict(cve_id="CVE-bad"), dict(story_url="javascript:alert(1)"), dict(asn=-1)]:
        with pytest.raises(ValidationError):
            NormalizedGeoEvent(**{**base, **bad})


def _story(**kw):
    from datetime import datetime

    from cvenom.schemas import NormalizedStory

    base = dict(url="https://example.com/a", source="s", title="t", summary="x",
                published=datetime(2026, 11, 1, tzinfo=UTC))
    return NormalizedStory(**{**base, **kw})


def _geo(**kw):
    from datetime import datetime

    from cvenom.schemas import NormalizedGeoEvent

    base = dict(source="x", external_id="1", kind="scan",
                observed_at=datetime(2026, 11, 1, tzinfo=UTC))
    return NormalizedGeoEvent(**{**base, **kw})


@pytest.mark.parametrize("year", [1969, 2101])
def test_story_and_geo_reject_years_outside_1970_2100(year):
    from datetime import datetime

    dt = datetime(year, 6, 1, tzinfo=UTC)
    with pytest.raises(ValidationError):
        _story(published=dt)
    with pytest.raises(ValidationError):
        _geo(observed_at=dt)


def test_future_dates_clamped_to_now_but_small_skew_kept():
    from datetime import datetime, timedelta

    now = datetime.now(UTC)
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


# --- .onion rejection (spec E) ---

@pytest.mark.parametrize("url", [
    "http://abcdef.onion/", "https://ABC.ONION/x", "http://abc.onion.:80/p", "http://sub.abc.onion",
    "http://onion/", "http://abc.onion../", "http://x%2Eonion/", "http://x%2eONION/",
    "http://x\u3002onion/", "http://x\uff0eonion/", "http://x\uff61onion/",
    "http://x.\uff4f\uff4e\uff49\uff4f\uff4e/",  # fullwidth letters (NFKC)
])
def test_validate_http_url_rejects_onion(url):
    from cvenom.schemas import validate_http_url

    with pytest.raises(ValueError):
        validate_http_url(url)


# I2: entity-obfuscated hosts. On the raw string `#` starts the fragment (host "x.onion&"), but ingest's
# sanitize_text decodes entities, so the stored/rendered URL points at a .onion host (or smuggles userinfo).
@pytest.mark.parametrize("url", [
    "http://x.onion&#46;/", "http://x&#46;onion/", "http://x.onion&#x2e;/p", "http://x.onion&amp;#46;/",
    "https://good.example&#64;leak.onion/", "http://x.onion&#46;:80/",
])
def test_validate_http_url_rejects_entity_obfuscated_onion(url):
    from cvenom.schemas import validate_http_url

    with pytest.raises(ValueError):
        validate_http_url(url)


# R10: markup in a URL can split ".onion" past every check once sanitize_text strips it at ingest.
@pytest.mark.parametrize("url", [
    "http://x.onion&lt;b&gt;/", "http://x&lt;b&gt;.onion&lt;/b&gt;/", "http://x.on&lt;i&gt;ion&lt;/i&gt;/",
    "http://x<b>.onion</b>/", "http://x.onion<!---->/", "http://x.on<i>ion</i>/a", "https://x.on<b>ion/",
    "x.oni&lt;b&gt;on", 'https://example.com/a"b', "https://example.com/a`b", "https://example.com/a&quot;b",
    "https://example.com/" + "a" * 2048,
])
def test_validate_http_url_rejects_markup_and_overlong(url):
    from cvenom.schemas import validate_http_url

    with pytest.raises(ValueError):
        validate_http_url(url)


def test_validate_http_url_overlong_nfkc_host_rejected_fast():
    import time

    from cvenom.schemas import validate_http_url

    start = time.perf_counter()
    with pytest.raises(ValueError):
        validate_http_url("https://" + "ﷺ" * 1_000_000 + "/")
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("url", ["https://example.com/?x=1&amp;y=2", "https://münchen.de/"])
def test_validate_http_url_still_accepts_legit(url):
    from cvenom.schemas import validate_http_url

    assert validate_http_url(url) == url


@pytest.mark.parametrize("text", ["x.on­ion", "x.on​ion", "x.on͏ion", "x.on️ion"])
def test_contains_onion_ignores_default_ignorables(text):
    from cvenom.schemas import contains_onion

    assert contains_onion(text)


# R11: variation-selector supplement and Hangul/Khmer fillers render as nothing.
@pytest.mark.parametrize("text", [
    "x.on\U000E0100ion", "x.onion\U000E01EF", "xㅤ.onion", "x.ᅟonion", "x.oᅠnion",
    "x.onﾠion", "x.oni឴on", "x.onio឵n", "exam\U000E0100ple.onion",
])
def test_contains_onion_ignores_fillers_and_vs_supplement(text):
    from cvenom.schemas import contains_onion

    assert contains_onion(text)


# R11: bidi controls reorder text visually; stripping cannot make that safe, so they are detected.
@pytest.mark.parametrize("text", [
    "‮noino.elpmaxe", "x.‮noino", "exa‪mple.com", "exa‫mple.com", "exa‬mple.com",
    "exa‭mple.com", "exa⁦mple.com", "exa⁧mple.com", "exa⁨mple.com",
    "exa⁩mple.com", "exa‎mple.com", "exa‏mple.com", "exa؜mple.com",
    "exa&#x202E;mple.com", "exa%E2%80%AEmple.com",
])
def test_contains_bidi_control_detects(text):
    from cvenom.schemas import contains_bidi_control

    assert contains_bidi_control(text)


@pytest.mark.parametrize("text", ["example.com", "bücher.de", "https://münchen.de/", "", "مثال.إختبار"])
def test_contains_bidi_control_negatives(text):
    from cvenom.schemas import contains_bidi_control

    assert not contains_bidi_control(text)


@pytest.mark.parametrize("url", [
    "https://‮noino.elpmaxe/", "https://exa⁧mple.com/", "https://example.com/a‮b",
    "https://example.com/a&#x202E;b", "https://xㅤ.onion/", "https://x.on\U000E0100ion/",
])
def test_validate_http_url_rejects_bidi_and_filler_onion(url):
    from cvenom.schemas import validate_http_url

    with pytest.raises(ValueError):
        validate_http_url(url)


@pytest.mark.parametrize("url", [
    "https://onion.example.com/", "https://example.com/x.onion", "https://example.com/?u=a.onion",
    "https://example.com/a?x=1&amp;y=2", "https://example.com/#frag&#46;onion",
])
def test_validate_http_url_allows_onion_lookalikes(url):
    from cvenom.schemas import validate_http_url

    assert validate_http_url(url) == url


@pytest.mark.parametrize("text", [
    "http://leak.onion/", "http://leak&#46;onion/", "http://leak&period;onion/",
    "http://leak&amp;#46;onion/", "http://leak%2Eonion/", "http://leak%252eonion/",
    "http://leak．onion/", "http://leak。onion/", "http://leak｡onion/",
    "LEAK.ＯＮＩＯＮ",
])
def test_contains_onion_normalises_like_ingest(text):
    from cvenom.schemas import contains_onion

    assert contains_onion(text)


@pytest.mark.parametrize("text", ["https://onion.example.com/", "victim.example", "", "onionring.example"])
def test_contains_onion_negatives(text):
    from cvenom.schemas import contains_onion

    assert not contains_onion(text)


def test_story_and_geo_reject_onion_urls():
    with pytest.raises(ValidationError):
        _story(url="http://abcdef.onion/leak")
    with pytest.raises(ValidationError):
        _geo(story_url="http://abcdef.onion/leak")


# --- KEV/NVD detail fields (spec D) ---

def test_normalized_cve_drops_bad_references_and_caps_20():
    refs = [{"url": f"https://ref{i}.example/a", "tags": ["Patch"]} for i in range(23)]
    refs.insert(3, {"url": "javascript:alert(1)", "tags": []})
    refs.insert(7, {"url": "http://leak.onion/x", "tags": []})
    assert len(refs) == 25
    c = NormalizedCve(cve_id="CVE-2026-1001", references=refs)
    assert len(c.references) == 20
    urls = [r.url for r in c.references]
    assert urls == [f"https://ref{i}.example/a" for i in range(20)]
    assert all(r.tags == ["Patch"] for r in c.references)


def test_references_drop_entity_obfuscated_onion():
    c = NormalizedCve(cve_id="CVE-2026-1001", references=[
        {"url": "http://x.onion&#46;/", "tags": []},
        {"url": "https://ok.example/", "tags": []},
    ])
    assert [r.url for r in c.references] == ["https://ok.example/"]


def test_references_drop_markup_split_onion():
    c = NormalizedCve(cve_id="CVE-2026-1001", references=[
        {"url": "http://x.on<i>ion</i>/a", "tags": []},
        {"url": "http://x.onion&lt;b&gt;/", "tags": []},
        {"url": "https://ok.example/", "tags": []},
    ])
    assert [r.url for r in c.references] == ["https://ok.example/"]


def test_references_bad_shapes_dropped_and_tags_bounded():
    c = NormalizedCve(cve_id="CVE-2026-1001", references=[
        "https://not-a-dict.example/", {"tags": ["x"]}, {"url": 5}, None,
        {"url": "https://ok.example/", "tags": ["a" * 64, "b" * 65, 7, *[f"t{i}" for i in range(12)]]},
    ])
    assert [r.url for r in c.references] == ["https://ok.example/"]
    tags = c.references[0].tags
    assert len(tags) == 10 and tags[0] == "a" * 64 and all(isinstance(t, str) and len(t) <= 64 for t in tags)
    assert NormalizedCve(cve_id="CVE-2026-1001", references="nope").references is None  # not provided
    assert NormalizedCve(cve_id="CVE-2026-1001", cwes="CWE-79").cwes is None


def test_cwes_filtered_and_capped():
    raw = ["CWE-79", "NVD-CWE-Other", "NVD-CWE-noinfo", "CWE-79", "cwe-20", "CWE-1234567", 89, "CWE-89"]
    raw += [f"CWE-{i}" for i in range(1000, 1030)]
    c = NormalizedCve(cve_id="CVE-2026-1001", cwes=raw)
    assert c.cwes[:2] == ["CWE-79", "CWE-89"]
    assert "NVD-CWE-Other" not in c.cwes
    assert len(c.cwes) == 20 and len(set(c.cwes)) == 20


def test_new_fields_default_to_none():
    c = NormalizedCve(cve_id="CVE-2026-1001")
    for f in ("kev_name", "kev_action", "kev_due", "kev_ransomware", "kev_notes", "cvss_vector",
              "cvss_severity", "cwes", "references", "last_modified"):
        assert getattr(c, f) is None, f


@pytest.mark.parametrize("raw, expected", [
    ("CRITICAL", "CRITICAL"), ("high", "HIGH"), ("NONE", "NONE"),
    ("SEVERE", None), ("", None), (5, None), (None, None),
])
def test_unknown_severity_is_none(raw, expected):
    assert NormalizedCve(cve_id="CVE-2026-1001", cvss_severity=raw).cvss_severity == expected


def test_cvss_vector_bounded_to_255():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert NormalizedCve(cve_id="CVE-2026-1001", cvss_vector=vec).cvss_vector == vec
    assert NormalizedCve(cve_id="CVE-2026-1001", cvss_vector="x" * 256).cvss_vector is None


@pytest.mark.parametrize("bad", [5, 3.1, ["CVSS:3.1"], {"v": 1}, True])
def test_non_string_cvss_vector_is_none(bad):
    c = NormalizedCve(cve_id="CVE-2026-1001", cvss=7.5, cvss_vector=bad)
    assert c.cvss_vector is None and c.cvss == 7.5  # the record is still created


def test_last_modified_bounded():
    from datetime import datetime

    naive = datetime(2026, 10, 1, 12)
    c = NormalizedCve(cve_id="CVE-2026-1001", last_modified=naive)
    assert c.last_modified == naive.replace(tzinfo=UTC)
    with pytest.raises(ValidationError):
        NormalizedCve(cve_id="CVE-2026-1001", last_modified=datetime(1900, 1, 1, tzinfo=UTC))


def test_story_details_defaults_to_empty_dict():
    assert _story().details == {}
    assert _story(details={"victim": "Acme"}).details == {"victim": "Acme"}
