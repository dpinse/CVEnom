"""Read models backing the API: CVE velocity, geo summary, loud stories."""

from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import func, or_, select

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


def _escape_like(q: str) -> str:
    return q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _story_dicts(session, stories) -> list[dict]:
    """Story rows -> API dicts with the sorted CVE ids linked to each (one query)."""
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


def loud_stories(
    session, now: datetime, *, limit: int = 50, exclude_sources: frozenset[str] = frozenset()
) -> list[dict]:
    now = _utc(now)
    limit = max(1, min(100, limit))
    since = now - timedelta(hours=get_settings().loud_window_hours)
    conds = [Story.published >= since]
    if exclude_sources:
        conds.append(Story.source.not_in(exclude_sources))
    stories = session.scalars(
        select(Story)
        .where(*conds)
        .order_by(Story.published.desc(), Story.id.desc())
        .limit(limit)
    ).all()
    return _story_dicts(session, stories)


def search_stories(
    session,
    *,
    q: str | None,
    source: str | None,
    start: datetime | None,
    end: datetime | None,
    page: int,
    page_size: int,
    exclude_sources: frozenset[str] = frozenset(),
) -> tuple[list[dict], int]:
    """History search. `end` is exclusive. exclude_sources applies to page and count."""
    conds = []
    if exclude_sources:
        conds.append(Story.source.not_in(exclude_sources))
    if q:
        pat = f"%{_escape_like(q)}%"
        conds.append(or_(Story.title.ilike(pat, escape="\\"), Story.summary.ilike(pat, escape="\\")))
    if source is not None:
        conds.append(Story.source == source)
    if start is not None:
        conds.append(Story.published >= start)
    if end is not None:
        conds.append(Story.published < end)
    total = session.scalar(select(func.count()).select_from(Story).where(*conds)) or 0
    rows = session.scalars(
        select(Story)
        .where(*conds)
        .order_by(Story.published.desc(), Story.id.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()
    return _story_dicts(session, rows), int(total)


def story_detail(session, url: str, exclude_sources: frozenset[str] = frozenset()) -> dict | None:
    conds = [Story.url == url]
    if exclude_sources:
        conds.append(Story.source.not_in(exclude_sources))
    s = session.scalars(select(Story).where(*conds).limit(1)).first()
    if s is None:
        return None
    return {**_story_dicts(session, [s])[0], "details": s.details or {}}
