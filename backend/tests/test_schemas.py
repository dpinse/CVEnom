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
