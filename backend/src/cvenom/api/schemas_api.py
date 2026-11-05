"""Explicit response models for the public read API (field allowlists)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated

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


class LanesOut(BaseModel):
    EXPLOITED: list[CveItem]
    LIKELY: list[CveItem]
    LOUD: list[CveItem]
    FRESH: list[CveItem]


class CveListOut(BaseModel):
    items: list[CveItem]
    page: int
    page_size: int
    total: int


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


class CveDetail(CveItem):
    epss: float | None
    affected: list
    stories: list[StoryRef]
    geo_events: list[GeoEventOut]


class VelocityPoint(BaseModel):
    day: date
    count: int


class VelocityOut(BaseModel):
    series: list[VelocityPoint]
    current: int
    rising: bool


class GeoSummaryItem(BaseModel):
    country_code: str
    kind: str
    magnitude: float
    events: int
    last_seen: UtcDatetime


class LoudStory(BaseModel):
    title: str
    summary: str
    url: str
    source: str
    published: UtcDatetime
    cve_ids: list[str]
