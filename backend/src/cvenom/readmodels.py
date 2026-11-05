"""Read models backing the API: CVE velocity, geo summary, loud stories."""

from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import func, select

from cvenom.config import get_settings
from cvenom.models import Cve, GeoEvent, Story, StoryCveLink


def _utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def cve_velocity(session, now: datetime, *, days: int) -> dict:
    now = _utc(now)
    today = now.date()
    first = today - timedelta(days=days - 1)
    start = datetime.combine(first, time.min, tzinfo=timezone.utc)
    end = datetime.combine(today + timedelta(days=1), time.min, tzinfo=timezone.utc)

    day_col = func.date(func.timezone("UTC", Cve.published)).label("day")
    rows = session.execute(
        select(day_col, func.count())
        .where(Cve.published.is_not(None), Cve.published >= start, Cve.published < end)
        .group_by(day_col)
    ).all()
    counts: dict[date, int] = {r[0]: int(r[1]) for r in rows}

    series = [
        {"day": first + timedelta(days=i), "count": counts.get(first + timedelta(days=i), 0)}
        for i in range(days)
    ]
    rising = False
    if days >= 14:
        last = sum(s["count"] for s in series[-7:])
        prior = sum(s["count"] for s in series[-14:-7])
        rising = last > prior  # equal window sizes: sum comparison == mean comparison
    return {"series": series, "current": series[-1]["count"] if series else 0, "rising": rising}


def geo_summary(session, now: datetime, *, window_hours: int = 24) -> list[dict]:
    now = _utc(now)
    since = now - timedelta(hours=window_hours)
    mag = func.sum(GeoEvent.magnitude).label("magnitude")
    rows = session.execute(
        select(
            GeoEvent.country_code,
            GeoEvent.kind,
            mag,
            func.count().label("events"),
            func.max(GeoEvent.observed_at).label("last_seen"),
        )
        .where(GeoEvent.country_code.is_not(None), GeoEvent.observed_at >= since)
        .group_by(GeoEvent.country_code, GeoEvent.kind)
        .order_by(mag.desc(), GeoEvent.country_code, GeoEvent.kind)
    ).all()
    return [
        {
            "country_code": r.country_code,
            "kind": r.kind,
            "magnitude": float(r.magnitude),
            "events": int(r.events),
            "last_seen": r.last_seen,
        }
        for r in rows
    ]


def loud_stories(session, now: datetime, *, limit: int = 50) -> list[dict]:
    now = _utc(now)
    limit = max(1, min(100, limit))
    since = now - timedelta(hours=get_settings().loud_window_hours)
    stories = session.scalars(
        select(Story)
        .where(Story.published >= since)
        .order_by(Story.published.desc(), Story.id.desc())
        .limit(limit)
    ).all()
    links: dict[int, list[str]] = {}
    if stories:
        agg = func.array_agg(StoryCveLink.cve_id).label("cve_ids")
        for sid, ids in session.execute(
            select(StoryCveLink.story_id, agg)
            .where(StoryCveLink.story_id.in_([s.id for s in stories]))
            .group_by(StoryCveLink.story_id)
        ):
            links[sid] = sorted(ids)
    return [
        {
            "title": s.title,
            "summary": s.summary,
            "url": s.url,
            "source": s.source,
            "published": s.published,
            "cve_ids": links.get(s.id, []),
        }
        for s in stories
    ]
