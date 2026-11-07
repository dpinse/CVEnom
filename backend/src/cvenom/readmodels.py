"""Read models backing the API: CVE velocity, geo summary, loud stories."""

from datetime import date, datetime, time, timedelta, timezone
from typing import Literal

from sqlalchemy import DateTime, Text, and_, case, cast, exists, func, literal, or_, select

from cvenom.config import get_settings
from cvenom.models import Cve, CveEvent, GeoEvent, Story, StoryCveLink
from cvenom.ranges import (
    DEFAULT_RANGE,
    RANGE_DAYS,
    RangeKey,
    range_start,
)


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


# --- Reusable "within R" predicates -------------------------------------
# Each returns a SQL clause over `Cve`. The dashboard summary counts and the
# Threats filters share these, so a count always equals what its link shows.


def exploited_since(now: datetime, days: int):
    """KEV listed on/after UTC today - days."""
    return and_(Cve.kev.is_(True), Cve.kev_added >= _utc(now).date() - timedelta(days=days))


def exploited_in_range(now: datetime, rng: RangeKey):
    """EXPLOITED lane membership: KEV listed on/after the range start date."""
    return exploited_since(now, RANGE_DAYS[rng])


def kev_due_within(now: datetime, days: int = 7):
    """KEV CVEs whose due date is in [UTC today, today + days]. Range-independent."""
    today = _utc(now).date()
    return and_(
        Cve.kev.is_(True),
        Cve.kev_due.is_not(None),
        Cve.kev_due >= today,
        Cve.kev_due <= today + timedelta(days=days),
    )


def fresh_since(now: datetime, days: int):
    """Not KEV, CVSS >= floor, published within `days`."""
    return and_(
        Cve.kev.is_not(True),
        Cve.cvss >= get_settings().fresh_cvss_floor,
        Cve.published >= _utc(now) - timedelta(days=days),
    )


def fresh_in_range(now: datetime, rng: RangeKey):
    """FRESH lane membership: not KEV, CVSS >= floor, published in range."""
    return fresh_since(now, RANGE_DAYS[rng])


def poc_since(now: datetime, days: int):
    """A `poc_published` cve_event occurred within `days`."""
    return exists(
        select(CveEvent.id).where(
            CveEvent.cve_id == Cve.cve_id,
            CveEvent.kind == "poc_published",
            CveEvent.occurred_at >= _utc(now) - timedelta(days=days),
        )
    )


def poc_in_range(now: datetime, rng: RangeKey):
    """A `poc_published` cve_event occurred in range (no lane requirement)."""
    return poc_since(now, RANGE_DAYS[rng])


def summary_counts(session, now: datetime, rng: RangeKey) -> dict:
    def n(pred) -> int:
        return int(session.scalar(select(func.count()).select_from(Cve).where(pred)) or 0)

    return {
        "range": rng,
        "new_kev": n(exploited_in_range(now, rng)),
        "kev_due_soon": n(kev_due_within(now)),
        "new_critical": n(fresh_in_range(now, rng)),
        "public_exploits": n(poc_in_range(now, rng)),
        "latest_kev_added": session.scalar(
            select(func.max(Cve.kev_added)).where(Cve.kev.is_(True))
        ),
    }


def cve_volume(session, now: datetime, rng: RangeKey) -> dict:
    """Published-CVE counts per severity bucket (hourly for 24h, else daily)."""
    now = _utc(now)
    if rng == "24h":
        unit, step, count = "hour", timedelta(hours=1), 24
        end = now.replace(minute=0, second=0, microsecond=0)
        first = end - timedelta(hours=count - 1)
    else:
        unit, step, count = "day", timedelta(days=1), RANGE_DAYS[rng]
        first_day = now.date() - timedelta(days=count - 1)
        first = datetime.combine(first_day, time.min, tzinfo=timezone.utc)
    stop = first + step * count
    bucket = func.date_trunc(unit, func.timezone("UTC", Cve.published))
    sev = case(
        (Cve.cvss >= 9, "crit"),
        (Cve.cvss >= 7, "high"),
        (Cve.cvss >= 4, "med"),
        else_="low",
    )
    in_window = (Cve.published >= first, Cve.published < stop)
    per: dict[tuple[datetime, str], int] = {
        (r[0].replace(tzinfo=timezone.utc), r[1]): int(r[2])
        for r in session.execute(
            select(bucket, sev, func.count())
            .where(*in_window, Cve.cvss.is_not(None))
            .group_by(bucket, sev)
        ).all()
    }
    buckets = []
    total = 0
    for i in range(count):
        b = first + step * i
        row = {k: per.get((b, k), 0) for k in ("crit", "high", "med", "low")}
        total += sum(row.values())
        buckets.append({"start": b, **row})
    unscored = int(
        session.scalar(
            select(func.count()).select_from(Cve).where(*in_window, Cve.cvss.is_(None))
        )
        or 0
    )
    return {"range": rng, "unit": unit, "buckets": buckets, "total": total, "unscored": unscored}


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


def country_activity(
    session, now: datetime, cc: str, *, window_hours: int, include_events: bool
) -> dict:
    """Activity for one country over the last `window_hours`.

    counts / top_sources / events cover `observed_at >= now - window_hours`
    (the same window as geo_summary, so the drawer agrees with the globe).
    trend is zero-filled, oldest first. For windows <= 168 h it is hourly UTC
    buckets, exactly `window_hours` points, the last being the current (partial)
    hour (`trend_unit == "hour"`); longer windows are daily buckets,
    `window_hours // 24` points, the last being today (`"day"`). top_cves lists
    up to 5 CVE ids by event count (public aggregate). Events are listed (newest first, max 50) only when
    `include_events`; the counts themselves are public aggregates.
    """
    now = _utc(now)
    since = now - timedelta(hours=window_hours)
    in_window = (GeoEvent.country_code == cc, GeoEvent.observed_at >= since)

    mag = func.sum(GeoEvent.magnitude)
    n = func.count()
    counts = [
        {"kind": r.kind, "events": int(r.events), "magnitude": float(r.magnitude)}
        for r in session.execute(
            select(GeoEvent.kind, n.label("events"), mag.label("magnitude"))
            .where(*in_window)
            .group_by(GeoEvent.kind)
            .order_by(n.desc(), GeoEvent.kind)
        ).all()
    ]
    top_sources = [
        {"source": r.source, "events": int(r.events)}
        for r in session.execute(
            select(GeoEvent.source, n.label("events"))
            .where(*in_window)
            .group_by(GeoEvent.source)
            .order_by(n.desc(), GeoEvent.source)
            .limit(5)
        ).all()
    ]

    if window_hours <= 168:
        trend_unit, unit_step, points = "hour", timedelta(hours=1), window_hours
        first = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=points - 1)
    else:
        trend_unit, unit_step, points = "day", timedelta(days=1), max(window_hours // 24, 1)
        first = datetime.combine(
            now.date() - timedelta(days=points - 1), time.min, tzinfo=timezone.utc
        )
    bucket = func.date_trunc(trend_unit, func.timezone("UTC", GeoEvent.observed_at))
    per_bucket = {
        r[0].replace(tzinfo=timezone.utc): int(r[1])
        for r in session.execute(
            select(bucket, func.count())
            .where(
                GeoEvent.country_code == cc,
                GeoEvent.observed_at >= first,
                GeoEvent.observed_at < first + unit_step * points,
            )
            .group_by(bucket)
        ).all()
    }
    trend = [
        {"bucket": b, "events": per_bucket.get(b, 0)}
        for b in (first + unit_step * i for i in range(points))
    ]

    top_cves = [
        {"cve_id": r.cve_id, "cvss": r.cvss, "events": int(r.events)}
        for r in session.execute(
            select(GeoEvent.cve_id, Cve.cvss, n.label("events"))
            .join(Cve, Cve.cve_id == GeoEvent.cve_id, isouter=True)
            .where(*in_window, GeoEvent.cve_id.is_not(None))
            .group_by(GeoEvent.cve_id, Cve.cvss)
            .order_by(n.desc(), GeoEvent.cve_id)
            .limit(5)
        ).all()
    ]

    events = None
    if include_events:
        events = [
            {
                "source": e.source,
                "kind": e.kind,
                "label": e.label,
                "magnitude": e.magnitude,
                "observed_at": e.observed_at,
                "asn": e.asn,
                "story_url": e.story_url,
                "details": e.details,
            }
            for e in session.execute(
                select(GeoEvent)
                .where(*in_window)
                .order_by(GeoEvent.observed_at.desc(), GeoEvent.id.desc())
                .limit(50)
            ).scalars()
        ]
    return {
        "country_code": cc,
        "window_hours": window_hours,
        "counts": counts,
        "top_sources": top_sources,
        "trend": trend,
        "trend_unit": trend_unit,
        "top_cves": top_cves,
        "events": events,
    }


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
    session,
    now: datetime,
    *,
    limit: int = 50,
    rng: RangeKey = DEFAULT_RANGE,
    exclude_sources: frozenset[str] = frozenset()
) -> list[dict]:
    now = _utc(now)
    limit = max(1, min(100, limit))
    conds = [Story.published >= range_start(now, rng)]
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
    include_sources: frozenset[str] = frozenset(),
) -> tuple[list[dict], int]:
    """History search. `end` is exclusive. exclude_sources applies to page and count;
    a non-empty include_sources keeps only those sources (exclude still wins)."""
    conds = []
    if include_sources:
        conds.append(Story.source.in_(include_sources))
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


# --- Threats search (GET /api/cves) --------------------------------------

AddedKey = Literal["any", "day", "week", "14d", "month", "90d", "year"]
ADDED_DAYS: dict[str, int] = {"day": 1, "week": 7, "14d": 14, "month": 30, "90d": 90, "year": 365}
StatusKey = Literal["all", "exploited", "likely", "news", "critical"]
SevKey = Literal["low", "med", "high", "crit"]
SEV_KEYS: tuple[str, ...] = ("low", "med", "high", "crit")
SortKey = Literal["newest", "hot", "trending", "due", "kev_added", "published", "cvss"]
TRENDING_DAYS = 7


def added_start(now: datetime, added: str) -> datetime | None:
    """Window start for an `added` key (None for `any`)."""
    return None if added == "any" else _utc(now) - timedelta(days=ADDED_DAYS[added])


def _sev_pred(key: str):
    if key == "crit":
        return Cve.cvss >= 9.0
    if key == "high":
        return and_(Cve.cvss >= 7.0, Cve.cvss < 9.0)
    if key == "med":
        return and_(Cve.cvss >= 4.0, Cve.cvss < 7.0)
    return and_(Cve.cvss >= 0.1, Cve.cvss < 4.0)


def product_label(c: Cve) -> str | None:
    """Short "what is affected" label: KEV vendor/product, NVD/OSV version entry, or CPE-ish."""
    affected = [a for a in (c.affected or []) if isinstance(a, str) and a]
    for a in affected:
        if ":" not in a:
            return a
    for v in c.affected_versions or []:
        if isinstance(v, dict) and isinstance(v.get("product"), str) and v["product"]:
            vendor = v.get("vendor")
            if v.get("source") == "NVD" and isinstance(vendor, str) and vendor:
                return f"{vendor} {v['product']}"
            return v["product"]
    if affected:
        tail = affected[0].split(":", 1)[1]
        return tail or None
    return None


def _visible_story(hidden: frozenset[str]) -> list:
    return [Story.source.not_in(hidden)] if hidden else []


def seen_expr(hidden: frozenset[str] = frozenset()):
    """GREATEST(published, kev_added 00:00 UTC, newest linked story); NULL-safe.

    `hidden` story sources (ransomware.live for anonymous callers) are excluded in SQL.
    """
    newest_story = (
        select(func.max(Story.published))
        .select_from(Story)
        .join(StoryCveLink, StoryCveLink.story_id == Story.id)
        .where(StoryCveLink.cve_id == Cve.cve_id, *_visible_story(hidden))
        .correlate(Cve)
        .scalar_subquery()
    )
    kev_day = func.timezone("UTC", cast(Cve.kev_added, DateTime))
    return func.greatest(Cve.published, kev_day, newest_story)


def last_seen_map(
    session, ids: list[str], hidden: frozenset[str] = frozenset()
) -> dict[str, datetime | None]:
    if not ids:
        return {}
    return dict(
        session.execute(select(Cve.cve_id, seen_expr(hidden)).where(Cve.cve_id.in_(ids))).all()
    )


def _story_count_since(since: datetime, hidden: frozenset[str]):
    return (
        select(func.count())
        .select_from(StoryCveLink)
        .join(Story, Story.id == StoryCveLink.story_id)
        .where(
            StoryCveLink.cve_id == Cve.cve_id, Story.published >= since, *_visible_story(hidden)
        )
        .correlate(Cve)
        .scalar_subquery()
    )


def _hot_expr(now: datetime, hidden: frozenset[str]):
    """SQL port of scoring.heat_rank (KEV gate, EPSS, CVSS, recency, news, no-patch)."""
    window = float(get_settings().fresh_window_hours)
    age_h = func.extract("epoch", literal(now, DateTime(timezone=True)) - Cve.published) / 3600.0
    recency = (
        func.coalesce(func.greatest(0.0, 1.0 - func.greatest(age_h, 0.0) / window) * 0.9, 0.0)
        if window > 0
        else literal(0.0)
    )
    news = func.least(_story_count_since(now - timedelta(days=TRENDING_DAYS), hidden), 10) * 0.05
    return (
        case((Cve.kev.is_(True), 1000.0), else_=0.0)
        + 100.0 * func.coalesce(Cve.epss_percentile, 0.0)
        + func.coalesce(Cve.cvss, 0.0)
        + recency
        + news
        + case((Cve.patch_available.is_(False), 0.25), else_=0.0)
    )


def cve_search_filters(
    now: datetime,
    *,
    added: str = "any",
    status: str = "all",
    exclude_kev: bool = False,
    sev: tuple[str, ...] = (),
    poc: bool | None = None,
    nopatch: bool | None = None,
    due: bool = False,
    q: str | None = None,
    hidden: frozenset[str] = frozenset(),
) -> list:
    """WHERE clauses for the Threats filters (everything except the legacy params).

    "Added" is: KEV add date when status=exploited; else the poc_published event time when
    poc=1; else the linked story's published time when status=news; else `published`.
    `due` (KEV due in [today, today+7]) ignores `added`, like the dashboard counter.
    """
    conds: list = []
    days = None if due else ADDED_DAYS.get(added)
    if status == "exploited":
        conds.append(exploited_since(now, days) if days else Cve.kev.is_(True))
    elif status == "likely":
        conds += [
            Cve.kev.is_not(True),
            Cve.epss_percentile >= get_settings().epss_percentile_threshold,
        ]
    elif status == "critical":
        conds.append(Cve.cvss >= 9.0)
    elif status == "news":
        link = (
            select(StoryCveLink.cve_id)
            .join(Story, Story.id == StoryCveLink.story_id)
            .where(StoryCveLink.cve_id == Cve.cve_id, *_visible_story(hidden))
        )
        if days:
            link = link.where(Story.published >= added_start(now, added))
        conds.append(exists(link))
    if exclude_kev:
        conds.append(Cve.kev.is_not(True))
    if poc:
        conds.append(poc_since(now, days) if days else Cve.poc_badge.is_(True))
    if nopatch:
        conds.append(Cve.patch_available.is_(False))
    if sev:
        conds.append(or_(*[_sev_pred(k) for k in sev]))
    if due:
        conds.append(kev_due_within(now, 7))
    # Plain published window: only when no other status/poc rule already defines "added".
    if days and status not in ("exploited", "news") and not poc:
        conds.append(Cve.published >= added_start(now, added))
    if q:
        pat = f"%{_escape_like(q)}%"
        conds.append(
            or_(
                Cve.cve_id.ilike(pat, escape="\\"),
                Cve.summary.ilike(pat, escape="\\"),
                Cve.kev_name.ilike(pat, escape="\\"),
                cast(Cve.affected, Text).ilike(pat, escape="\\"),
            )
        )
    return conds


def cve_search_order(
    now: datetime, sort: str, *, status: str = "all", hidden: frozenset[str] = frozenset()
) -> tuple:
    if sort == "hot":
        return (_hot_expr(now, hidden).desc(), Cve.cve_id)
    if sort == "trending":
        return (
            _story_count_since(now - timedelta(days=TRENDING_DAYS), hidden).desc(),
            Cve.epss_percentile.desc().nulls_last(),
            Cve.published.desc().nulls_last(),
            Cve.cve_id,
        )
    if sort == "due":
        return (Cve.kev_due.asc(), Cve.cve_id)
    if sort == "kev_added":  # legacy History order
        return (Cve.kev_added.desc().nulls_last(), Cve.cve_id)
    if sort == "newest" and status == "exploited":
        return (Cve.kev_added.desc().nulls_last(), Cve.published.desc().nulls_last(), Cve.cve_id)
    if sort == "cvss":
        return (Cve.cvss.desc().nulls_last(), Cve.published.desc().nulls_last(), Cve.cve_id)
    return (Cve.published.desc().nulls_last(), Cve.cve_id)
