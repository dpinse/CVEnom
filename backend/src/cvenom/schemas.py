import re
from datetime import date, datetime, timedelta, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

# ASCII digits only (no Unicode digits), anchored on the whole string via fullmatch.
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.ASCII)
COUNTRY_RE = re.compile(r"[A-Z]{2}", re.ASCII)
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
MIN_YEAR, MAX_YEAR = 1970, 2100
MAX_FUTURE_SKEW = timedelta(hours=1)


def bound_datetime(value: datetime) -> datetime:
    """Aware UTC; reject years outside 1970..2100; clamp >1h-future values to now."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    try:
        value = value.astimezone(timezone.utc)
    except (OverflowError, OSError) as exc:
        raise ValueError("datetime out of range") from exc
    if not MIN_YEAR <= value.year <= MAX_YEAR:
        raise ValueError(f"datetime year {value.year} outside {MIN_YEAR}..{MAX_YEAR}")
    now = datetime.now(timezone.utc)
    return now if value - now > MAX_FUTURE_SKEW else value


def validate_cve_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("cve_id must be a string")
    normalized = value.strip().upper()
    if not CVE_ID_RE.fullmatch(normalized):
        raise ValueError(f"invalid cve_id {value!r}")
    return normalized


def validate_http_url(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("url must be a string")
    url = value.strip()
    if not url or _BAD_URL_CHARS.search(url):
        raise ValueError("url is empty or contains whitespace/control characters")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ValueError(f"invalid url: {exc}") from exc
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        raise ValueError("url must be http(s) with a host")
    if parts.username or parts.password:
        raise ValueError("url must not contain userinfo")
    return url


class NormalizedCve(BaseModel):
    cve_id: str

    @field_validator("cve_id", mode="before")
    @classmethod
    def _validate_cve_id(cls, value: object) -> str:
        return validate_cve_id(value)

    published: datetime | None = None
    cvss: float | None = Field(default=None, ge=0, le=10, allow_inf_nan=False)
    epss: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    epss_percentile: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    kev: bool = False
    kev_added: date | None = None
    kev_source: str | None = None
    poc_badge: bool = False
    patch_available: bool | None = None
    affected: list[str] = Field(default_factory=list)
    summary: str | None = None


class NormalizedStory(BaseModel):
    url: str
    source: str
    title: str
    summary: str
    published: datetime

    @field_validator("url", mode="before")
    @classmethod
    def _validate_url(cls, value: object) -> str:
        return validate_http_url(value)

    @field_validator("published")
    @classmethod
    def _bound_published(cls, value: datetime) -> datetime:
        return bound_datetime(value)


class NormalizedGeoEvent(BaseModel):
    source: str
    external_id: str = Field(min_length=1, max_length=256)
    kind: Literal["scan", "outage", "victim", "c2", "bgp"]
    country_code: str | None = None
    asn: int | None = Field(default=None, ge=0, le=4294967295)
    observed_at: datetime
    magnitude: float = Field(default=1.0, ge=0, allow_inf_nan=False)
    label: str | None = None  # stored raw; the pipeline sanitizes
    cve_id: str | None = None
    story_url: str | None = None
    details: dict = Field(default_factory=dict)

    @field_validator("external_id")
    @classmethod
    def _validate_external_id(cls, value: str) -> str:
        if not value.strip() or _CONTROL_CHARS.search(value):
            raise ValueError("external_id is blank or contains control characters")
        return value

    @field_validator("country_code", mode="before")
    @classmethod
    def _validate_country(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("country_code must be a string")
        code = value.upper()
        if not COUNTRY_RE.fullmatch(code):
            raise ValueError(f"invalid country_code {value!r}")
        return code

    @field_validator("cve_id", mode="before")
    @classmethod
    def _validate_cve(cls, value: object) -> str | None:
        return None if value is None else validate_cve_id(value)

    @field_validator("story_url", mode="before")
    @classmethod
    def _validate_story_url(cls, value: object) -> str | None:
        return None if value is None else validate_http_url(value)

    @field_validator("observed_at")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return bound_datetime(value)
