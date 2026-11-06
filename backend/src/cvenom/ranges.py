"""Shared time-range vocabulary for the radar: one definition of "within R"."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Literal

RangeKey = Literal["24h", "7d", "14d", "30d"]
DEFAULT_RANGE: RangeKey = "7d"
RANGE_DAYS: dict[str, int] = {"24h": 1, "7d": 7, "14d": 14, "30d": 30}


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def range_start(now: datetime, rng: RangeKey) -> datetime:
    return _utc(now) - timedelta(days=RANGE_DAYS[rng])


def range_start_date(now: datetime, rng: RangeKey) -> date:
    return _utc(now).date() - timedelta(days=RANGE_DAYS[rng])
