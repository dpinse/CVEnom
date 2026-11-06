"""Explicit response models for the public read API (field allowlists)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, PlainSerializer


def _to_utc(v: datetime) -> datetime:
    return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)


UtcDatetime = Annotated[datetime, PlainSerializer(_to_utc, return_type=datetime)]


class CveItem(BaseModel):
    cve_id: str
    cvss: float | None
    epss_percentile: float | None
    kev: bool
    kev_added: date | None
    kev_source: str | None
    poc_badge: bool
    patch_available: bool | None
    published: UtcDatetime | None
    summary: str
    recent_story_count: int
    product: str | None
    last_seen: UtcDatetime | None


class LaneOut(BaseModel):
    total: int
    items: list[CveItem]


class LanesOut(BaseModel):
    EXPLOITED: LaneOut
    LIKELY: LaneOut
    LOUD: LaneOut
    FRESH: LaneOut


class CveListOut(BaseModel):
    items: list[CveItem]
    page: int
    page_size: int
    total: int
    # q was an exact CVE id (all other filters ignored); filtered_out = it exists but the
    # other filters would have hidden it.
    exact_match: bool = False
    exact_match_filtered_out: bool = False


class StoryRef(BaseModel):
    title: str
    url: str
    source: str
    published: UtcDatetime


class GeoEventOut(BaseModel):
    kind: str
    country_code: str | None
    label: str | None
    magnitude: float
    observed_at: UtcDatetime
    details: dict


class CveReferenceOut(BaseModel):
    url: str
    tags: list[str]


class CveDetail(CveItem):
    epss: float | None
    affected: list
    kev_name: str | None
    kev_action: str | None
    kev_due: date | None
    kev_ransomware: bool | None
    kev_notes: str | None
    cvss_vector: str | None
    cvss_severity: str | None
    cwes: list[str]
    references: list[CveReferenceOut]
    last_modified: UtcDatetime | None
    stories: list[StoryRef]
    geo_events: list[GeoEventOut]


class VelocityPoint(BaseModel):
    day: date
    count: int


class VelocityOut(BaseModel):
    series: list[VelocityPoint]
    current: int
    rising: bool


class SummaryOut(BaseModel):
    range: str
    new_kev: int
    kev_due_soon: int
    new_critical: int
    public_exploits: int
    latest_kev_added: date | None


class VolumeBucket(BaseModel):
    start: UtcDatetime
    crit: int
    high: int
    med: int
    low: int


class VolumeOut(BaseModel):
    range: str
    unit: Literal["hour", "day"]
    buckets: list[VolumeBucket]
    total: int
    unscored: int


class GeoSummaryItem(BaseModel):
    country_code: str
    kind: str
    magnitude: float
    events: int
    last_seen: UtcDatetime


class CountryCount(BaseModel):
    kind: str
    events: int
    magnitude: float


class CountrySource(BaseModel):
    source: str
    events: int


class CountryTrendPoint(BaseModel):
    bucket: UtcDatetime
    events: int


class CountryTopCve(BaseModel):
    cve_id: str
    cvss: float | None
    events: int


class CountryEventOut(BaseModel):
    source: str
    kind: str
    label: str | None
    magnitude: float
    observed_at: UtcDatetime
    asn: int | None
    story_url: str | None
    details: dict


class CountryActivityOut(BaseModel):
    country_code: str
    window_hours: int
    counts: list[CountryCount]
    top_sources: list[CountrySource]
    trend: list[CountryTrendPoint]
    trend_unit: Literal["hour", "day"]
    top_cves: list[CountryTopCve]
    events: list[CountryEventOut] | None


class StoryItem(BaseModel):
    title: str
    summary: str
    url: str
    source: str
    published: UtcDatetime
    cve_ids: list[str]


LoudStory = StoryItem


class StoryListOut(BaseModel):
    items: list[StoryItem]
    page: int
    page_size: int
    total: int


class StoryDetailOut(StoryItem):
    details: dict
