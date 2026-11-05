"""Public read API: lanes, CVE search/detail, velocity, geo, loud stories."""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Literal
from urllib.parse import unquote_to_bytes

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import String, any_, func, literal, or_, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Session

from cvenom.config import get_settings
from cvenom.models import Cve, GeoEvent, Story, StoryCveLink
from cvenom.pipeline import lane_views
from cvenom.readmodels import cve_velocity, geo_summary, loud_stories
from cvenom.schemas import CVE_ID_RE
from cvenom.scoring import Lane

from cvenom.models import User

from .deps import SessionDep, public_or_user, restricted_sources
from .ratelimit import rate_limit
from .schemas_api import (
    CveDetail,
    CveListOut,
    GeoEventOut,
    GeoSummaryItem,
    LanesOut,
    LoudStory,
    StoryRef,
    VelocityOut,
)

# Cached routes must not vary on request headers (see ResponseCacheMiddleware).
CACHE_PATHS: dict[str, frozenset[str]] = {
    "/api/lanes": frozenset(),
    "/api/velocity": frozenset({"days"}),
    "/api/geo": frozenset({"window_hours"}),
    "/api/stories/loud": frozenset({"limit"}),
}

LANE_CAP = 100


def _utf8_query(request: Request) -> None:
    """Starlette decodes %FF to U+FFFD silently; reject non-UTF8 explicitly."""
    raw = request.scope.get("query_string", b"").replace(b"+", b" ")
    try:
        decoded = unquote_to_bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail={"error": "validation_error"}) from None
    if "\x00" in decoded:  # psycopg rejects NUL in text params (would be a 500)
        raise HTTPException(status_code=422, detail={"error": "validation_error"})


# The limiter MUST precede public_or_user: otherwise invalid-token and (with
# public_read=False) anonymous requests get a 401 before they are counted.
router = APIRouter(
    prefix="/api",
    dependencies=[Depends(_utf8_query), Depends(rate_limit("read")), Depends(public_or_user)],
)


def _now() -> datetime:
    return datetime.now(UTC)


def _item(c: Cve, story_count: int) -> dict:
    return {
        "cve_id": c.cve_id,
        "cvss": c.cvss,
        "epss_percentile": c.epss_percentile,
        "kev": c.kev,
        "kev_added": c.kev_added,
        "kev_source": c.kev_source,
        "poc_badge": c.poc_badge,
        "patch_available": c.patch_available,
        "published": c.published,
        "summary": c.summary,
        "recent_story_count": story_count,
    }


def _recent_counts(session: Session, ids: list[str]) -> dict[str, int]:
    if not ids:
        return {}
    cutoff = _now() - timedelta(hours=get_settings().loud_window_hours)
    return dict(
        session.execute(
            select(StoryCveLink.cve_id, func.count())
            .join(Story, Story.id == StoryCveLink.story_id)
            .where(StoryCveLink.cve_id.in_(ids), Story.published >= cutoff)
            .group_by(StoryCveLink.cve_id)
        ).all()
    )


@router.get("/lanes", response_model=LanesOut)
def lanes(session: Session = SessionDep) -> dict:
    views = lane_views(session, _now())
    capped = {lane: v[:LANE_CAP] for lane, v in views.items()}
    ids = list({v.cve_id for vs in capped.values() for v in vs})
    rows: dict[str, Cve] = {}
    if ids:  # ONE query for the fields CveView lacks
        rows = {c.cve_id: c for c in session.scalars(select(Cve).where(Cve.cve_id.in_(ids)))}
    out: dict[str, list[dict]] = {}
    for lane in Lane:
        items = []
        for v in capped.get(lane, []):
            c = rows.get(v.cve_id)
            if c is not None:
                items.append(_item(c, v.recent_story_count))
        out[lane.value] = items
    return out


def _escape_like(q: str) -> str:
    return q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/cves", response_model=CveListOut)
def search_cves(
    q: Annotated[str | None, Query(max_length=200)] = None,
    source: Literal["cisa", "vulncheck"] | None = None,
    lane: Lane | None = None,
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    kev: bool | None = None,
    from_: Annotated[date | None, Query(alias="from")] = None,
    to: date | None = None,
    page: Annotated[int, Query(ge=1, le=10000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    session: Session = SessionDep,
) -> dict:
    conds = []
    if q:
        pat = f"%{_escape_like(q)}%"
        conds.append(
            or_(Cve.cve_id.ilike(pat, escape="\\"), Cve.summary.ilike(pat, escape="\\"))
        )
    if source is not None:
        conds.append(Cve.kev_source == source)
    if min_cvss is not None:
        conds.append(Cve.cvss >= min_cvss)
    if kev is not None:
        conds.append(Cve.kev.is_(kev))
    if from_ is not None:  # range predicates keep the BRIN index usable
        conds.append(Cve.published >= datetime.combine(from_, time.min, tzinfo=UTC))
    if to is not None and to < date.max:
        conds.append(Cve.published < datetime.combine(to + timedelta(days=1), time.min, tzinfo=UTC))
    if lane is not None:
        members = [v.cve_id for v in lane_views(session, _now())[lane]]
        conds.append(Cve.cve_id == any_(literal(members, ARRAY(String))))

    total = session.scalar(select(func.count()).select_from(Cve).where(*conds)) or 0
    rows = session.scalars(
        select(Cve)
        .where(*conds)
        .order_by(Cve.published.desc().nulls_last(), Cve.cve_id)
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()
    counts = _recent_counts(session, [r.cve_id for r in rows])
    return {
        "items": [_item(r, counts.get(r.cve_id, 0)) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/cves/{cve_id:path}", response_model=CveDetail)
def cve_detail(
    cve_id: str,
    session: Session = SessionDep,
    user: User | None = Depends(public_or_user),
):
    hidden = restricted_sources(user)
    # Exact, case-sensitive match (the shared normalising validator is too lenient here).
    if not CVE_ID_RE.fullmatch(cve_id):
        return JSONResponse({"error": "not_found"}, status_code=404)
    c = session.get(Cve, cve_id)
    if c is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    stories = session.execute(
        select(Story.title, Story.url, Story.source, Story.published)
        .join(StoryCveLink, StoryCveLink.story_id == Story.id)
        .where(StoryCveLink.cve_id == cve_id, Story.source.not_in(hidden))
        .order_by(Story.published.desc(), Story.id.desc())
        .limit(50)
    ).all()
    geo = session.execute(
        select(
            GeoEvent.kind,
            GeoEvent.country_code,
            GeoEvent.label,
            GeoEvent.magnitude,
            GeoEvent.observed_at,
            GeoEvent.details,
        )
        .where(GeoEvent.cve_id == cve_id, GeoEvent.source.not_in(hidden))
        .order_by(GeoEvent.observed_at.desc(), GeoEvent.id.desc())
        .limit(100)
    ).all()
    counts = _recent_counts(session, [cve_id])
    return {
        **_item(c, counts.get(cve_id, 0)),
        "epss": c.epss,
        "affected": c.affected,
        "stories": [StoryRef(**r._asdict()) for r in stories],
        "geo_events": [GeoEventOut(**r._asdict()) for r in geo],
    }


@router.get("/velocity", response_model=VelocityOut)
def velocity(
    days: Annotated[int, Query(ge=1, le=30)] = 30, session: Session = SessionDep
) -> dict:
    return cve_velocity(session, _now(), days=days)


@router.get("/geo", response_model=list[GeoSummaryItem])
def geo(
    window_hours: Annotated[int, Query(ge=1, le=168)] = 24, session: Session = SessionDep
) -> list[dict]:
    return geo_summary(session, _now(), window_hours=window_hours)


@router.get("/stories/loud", response_model=list[LoudStory])
def stories_loud(
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    session: Session = SessionDep,
    user: User | None = Depends(public_or_user),
) -> list[dict]:
    return loud_stories(session, _now(), limit=limit, exclude_sources=restricted_sources(user))
