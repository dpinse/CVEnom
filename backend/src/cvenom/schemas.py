import html
import re
import unicodedata
from datetime import date, datetime, timedelta, timezone
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, Field, ValidationError, field_validator

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


# IDNA label separators that WHATWG URL parsing maps to "." (ideographic, fullwidth, halfwidth).
_IDNA_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


_NORMALISE_MAX_ROUNDS = 10


def normalize_onion_text(value: str) -> str:
    """Normalise text the way a browser (and our ingest sanitiser) would read it.

    Repeats until stable (bounded): HTML-entity decode (ingest's sanitize_text decodes
    entities to a fixed point, so `&#46;` becomes `.`), percent-decode, NFKC (fullwidth
    letters/dots), map the IDNA dot separators to "."; then lower-case.
    """
    text = value
    for _ in range(_NORMALISE_MAX_ROUNDS):
        prev = text
        text = unicodedata.normalize("NFKC", unquote(html.unescape(text))).translate(_IDNA_DOTS)
        if text == prev:
            break
    return text.lower()


def contains_onion(text: str) -> bool:
    """True if `text`, once normalised, mentions a `.onion` name anywhere."""
    return ".onion" in normalize_onion_text(text)


def _is_onion_host(hostname: str) -> bool:
    """True if the host is (or ends in) .onion as a browser would see it.

    Normalises like WHATWG host parsing does before the check (see normalize_onion_text),
    then drops trailing dots.
    """
    host = normalize_onion_text(hostname).rstrip(".")
    return host == "onion" or host.endswith(".onion")


def _check_http_url(url: str) -> None:
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
    if _is_onion_host(parts.hostname or ""):
        raise ValueError("onion urls are not allowed")


def _entity_decoded(url: str) -> str:
    """The URL as ingest stores it and the frontend reads it: HTML entities decoded to a fixed point."""
    text = url
    for _ in range(_NORMALISE_MAX_ROUNDS):
        decoded = html.unescape(text)
        if decoded == text:
            return text
        text = decoded
    raise ValueError("url entity encoding does not settle")


def validate_http_url(value: object) -> str:
    """Accept an http(s) URL with a host, no userinfo and no .onion host; return it unchanged (stripped).

    The checks run on the raw string and again on its entity-decoded form: on the raw string
    `http://x.onion&#46;/` has the host `x.onion&` (`#` starts the fragment), but sanitize_text
    decodes it to `http://x.onion./` before it is stored. Only the host is checked for .onion, so
    `https://example.com/x.onion` and `https://onion.example.com/` still pass.
    """
    if not isinstance(value, str):
        raise ValueError("url must be a string")
    url = value.strip()
    _check_http_url(url)
    decoded = _entity_decoded(url)
    if decoded != url:
        _check_http_url(decoded)
    return url


CWE_RE = re.compile(r"CWE-\d{1,6}", re.ASCII)
CvssSeverity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEVERITIES = frozenset(("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"))
MAX_REFERENCES = 20
MAX_CWES = 20
MAX_REF_TAGS = 10
MAX_REF_TAG_LEN = 64
MAX_CVSS_VECTOR_LEN = 255


class CveReference(BaseModel):
    url: str
    tags: list[str] = Field(default_factory=list)

    @field_validator("url", mode="before")
    @classmethod
    def _validate_url(cls, value: object) -> str:
        return validate_http_url(value)

    @field_validator("tags", mode="before")
    @classmethod
    def _bound_tags(cls, value: object) -> list[str]:
        """Keep only str tags of <= 64 chars, at most 10; never fails the reference."""
        if not isinstance(value, (list, tuple)):
            return []
        return [t for t in value if isinstance(t, str) and len(t) <= MAX_REF_TAG_LEN][:MAX_REF_TAGS]


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
    # KEV catalog detail (CISA / VulnCheck) and NVD detail. None = "not provided":
    # upsert_cve leaves the stored value alone, so a KEV record never wipes NVD lists.
    kev_name: str | None = None
    kev_action: str | None = None
    kev_due: date | None = None
    kev_ransomware: bool | None = None
    kev_notes: str | None = None
    cvss_vector: str | None = None
    cvss_severity: CvssSeverity | None = None
    cwes: list[str] | None = None
    references: list[CveReference] | None = None
    last_modified: datetime | None = None

    @field_validator("cvss_vector", mode="before")
    @classmethod
    def _bound_vector(cls, value: object) -> str | None:
        # A non-string or overlong vector (column is String(255)) is dropped, never fails the record.
        if not isinstance(value, str) or len(value) > MAX_CVSS_VECTOR_LEN:
            return None
        return value

    @field_validator("cvss_severity", mode="before")
    @classmethod
    def _known_severity(cls, value: object) -> str | None:
        if isinstance(value, str) and value.strip().upper() in _SEVERITIES:
            return value.strip().upper()
        return None  # unknown severity never fails the record

    @field_validator("cwes", mode="before")
    @classmethod
    def _filter_cwes(cls, value: object) -> list[str] | None:
        """Keep ``CWE-<1..6 digits>`` only (drops NVD-CWE-Other etc.), deduped in order, max 20."""
        if not isinstance(value, (list, tuple)):
            return None
        kept = [c for c in value if isinstance(c, str) and CWE_RE.fullmatch(c)]
        return list(dict.fromkeys(kept))[:MAX_CWES]

    @field_validator("references", mode="before")
    @classmethod
    def _filter_references(cls, value: object) -> list[CveReference] | None:
        """Drop invalid entries (bad/onion/non-http url, bad shape), cap at 20; never fails."""
        if not isinstance(value, (list, tuple)):
            return None
        kept: list[CveReference] = []
        for item in value:
            if len(kept) >= MAX_REFERENCES:
                break
            try:
                kept.append(CveReference.model_validate(item))
            except ValidationError:
                continue
        return kept

    @field_validator("last_modified")
    @classmethod
    def _bound_last_modified(cls, value: datetime | None) -> datetime | None:
        return None if value is None else bound_datetime(value)


class NormalizedStory(BaseModel):
    url: str
    source: str
    title: str
    summary: str
    published: datetime
    details: dict = Field(default_factory=dict)  # stored raw; the pipeline sanitizes

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
