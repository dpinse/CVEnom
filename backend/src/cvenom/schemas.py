import re
from datetime import date, datetime

from pydantic import BaseModel, Field, field_validator

# ASCII digits only (no Unicode digits), anchored on the whole string via fullmatch.
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII)


class NormalizedCve(BaseModel):
    cve_id: str

    @field_validator("cve_id", mode="before")
    @classmethod
    def _validate_cve_id(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("cve_id must be a string")
        normalized = value.strip().upper()
        if not CVE_ID_RE.fullmatch(normalized):
            raise ValueError(f"invalid cve_id {value!r}")
        return normalized
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
