"""Lane-scoring engine: pure logic, no DB."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum

from cvenom.config import Settings
from cvenom.ranges import DEFAULT_RANGE, RangeKey, range_start, range_start_date


class Lane(str, Enum):
    EXPLOITED = "EXPLOITED"
    LIKELY = "LIKELY"
    LOUD = "LOUD"
    FRESH = "FRESH"


@dataclass
class CveView:
    cve_id: str
    published: datetime | None
    cvss: float | None
    epss_percentile: float | None
    kev: bool
    recent_story_count: int = 0
    patch_available: bool | None = None
    poc_badge: bool = False
    kev_added: date | None = None
    kev_ransomware: bool | None = None


def recent_kev_cutoff(now: datetime) -> date:
    """kev_added is a DATE: "recently added" = today or yesterday (UTC). Keep in sync with
    isRecentKevDate in frontend/src/lib/situation.ts."""
    return _utc(now).date() - timedelta(days=1)


def priority_key(v: CveView, now: datetime) -> tuple:
    """Shared "priority" order (SQL twin: readmodels.priority_order): recently added KEV first, then ransomware, EPSS desc,
    CVSS desc (NULLs last), PoC first, no-patch first, newest KEV, then CVE id."""
    recent = v.kev_added is not None and v.kev_added >= recent_kev_cutoff(now)
    return (
        not recent,  # 48h boost: expires on its own as kev_added ages
        v.kev_ransomware is not True,
        v.epss_percentile is None,
        -(v.epss_percentile or 0.0),
        v.cvss is None,
        -(v.cvss or 0.0),
        not v.poc_badge,
        v.patch_available is not False,
        v.kev_added is None,
        -(v.kev_added.toordinal() if v.kev_added else 0),
        v.cve_id,
    )


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def lanes_for_cve(
    v: CveView, now: datetime, cfg: Settings, rng: RangeKey = DEFAULT_RANGE
) -> set[Lane]:
    lanes: set[Lane] = set()
    if v.kev and v.kev_added is not None and v.kev_added >= range_start_date(now, rng):
        lanes.add(Lane.EXPLOITED)
    if (
        not v.kev
        and v.epss_percentile is not None
        and v.epss_percentile >= cfg.epss_percentile_threshold
        and v.published is not None
        and _utc(now) - _utc(v.published) <= timedelta(days=cfg.likely_window_days)
    ):
        lanes.add(Lane.LIKELY)
    if v.recent_story_count >= 1:
        lanes.add(Lane.LOUD)
    if (
        not v.kev
        and v.published is not None
        and v.cvss is not None
        and v.cvss >= cfg.fresh_cvss_floor
        and _utc(v.published) >= range_start(now, rng)
    ):
        lanes.add(Lane.FRESH)
    return lanes


def heat_rank(v: CveView, now: datetime, cfg: Settings) -> float:
    """Ordering within lanes.

    KEV is a strict gate (+1000 exceeds the max of all other terms). The epss,
    cvss, recency and story terms are a weighted sort and may overlap.
    """
    score = 1000.0 if v.kev else 0.0
    score += 100.0 * (v.epss_percentile or 0.0)
    score += (v.cvss or 0.0)  # 0..10
    window = float(cfg.fresh_window_hours)
    if v.published is not None and window > 0:
        age_h = max((_utc(now) - _utc(v.published)).total_seconds() / 3600.0, 0.0)
        score += max(0.0, 1.0 - age_h / window) * 0.9  # 0..0.9
    score += min(v.recent_story_count, 10) * 0.05  # 0..0.5
    if v.patch_available is False:
        score += 0.25
    return score
