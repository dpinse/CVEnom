from datetime import date, datetime

from pydantic import BaseModel, Field


class NormalizedCve(BaseModel):
    cve_id: str
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
