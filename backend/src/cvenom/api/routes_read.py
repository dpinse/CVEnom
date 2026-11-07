"""Public read API: lanes, CVE search/detail, velocity, geo, loud stories."""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Literal
from urllib.parse import unquote_to_bytes

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import String, any_, func, literal, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Session

from cvenom.config import get_settings
from cvenom.models import Cve, CveEvent, GeoEvent, Story, StoryCveLink, User
from cvenom.pipeline import lane_views
from cvenom.readmodels import (
    ADDED_DAYS,
    SEV_KEYS,
    AddedKey,
    SortKey,
    StatusKey,
    country_activity,
    cve_search_filters,
    cve_search_order,
    cve_velocity,
    cve_volume,
    geo_summary,
    last_seen_map,
    loud_stories,
    product_label,
    search_stories,
    story_detail,
    summary_counts,
)
from cvenom.ranges import DEFAULT_RANGE, RANGE_DAYS, RangeKey, range_start
from cvenom.schemas import CVE_ID_RE, AffectedVersion, validate_http_url
from cvenom.scoring import Lane

from .deps import (
    RESTRICTED_SOURCES,
    SessionDep,
    current_user,
    public_or_user,
    restricted_sources,
)
from .ratelimit import rate_limit
from .schemas_api import (
    AffectedVersionOut,
    CountryActivityOut,
    CveDetail,
    CveEventOut,
    CveListOut,
    CveReferenceOut,
    GeoEventOut,
    GeoSummaryItem,
    GeoTop,
    LanesOut,
    LoudStory,
    RelatedCve,
    StoryDetailOut,
    StoryListOut,
    StoryRef,
    SummaryOut,
    VelocityOut,
    VolumeOut,
)

# Cached routes must not vary on request headers (see ResponseCacheMiddleware).
CACHE_PATHS: dict[str, frozenset[str]] = {
    "/api/lanes": frozenset({"range", "limit"}),
    "/api/velocity": frozenset({"days"}),
    "/api/summary": frozenset({"range"}),
    "/api/volume": frozenset({"range"}),
    "/api/geo": frozenset({"window_hours", "range"}),
    "/api/stories/loud": frozenset({"limit", "range"}),
    # free-text `q` is not allowed: it bypasses the cache so arbitrary strings cannot fill Redis
    "/api/stories": frozenset({"source", "kind", "from", "to", "added", "page", "page_size"}),
}

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


def _loud_since() -> datetime:
    return _now() - timedelta(hours=get_settings().loud_window_hours)


def _parse_sev(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys or any(k not in SEV_KEYS for k in keys):
        raise HTTPException(status_code=422, detail={"error": "validation_error"})
    return tuple(dict.fromkeys(keys))


def _item(c: Cve, story_count: int, last_seen: datetime | None) -> dict:
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
        "product": product_label(c),
        "last_seen": last_seen,
    }


def _recent_counts(
    session: Session, ids: list[str], since: datetime, hidden: frozenset[str] = frozenset()
) -> dict[str, int]:
    if not ids:
        return {}
    return dict(
        session.execute(
            select(StoryCveLink.cve_id, func.count())
            .join(Story, Story.id == StoryCveLink.story_id)
            .where(
                StoryCveLink.cve_id.in_(ids),
                Story.published >= since,
                Story.source.not_in(hidden),
            )
            .group_by(StoryCveLink.cve_id)
        ).all()
    )


@router.get("/lanes", response_model=LanesOut)
def lanes(
    range_: Annotated[RangeKey, Query(alias="range")] = DEFAULT_RANGE,
    limit: Annotated[int, Query(ge=1, le=100)] = 5,
    session: Session = SessionDep,
    user: User | None = Depends(current_user),  # gated by the router-level public_or_user
) -> dict:
    hidden = restricted_sources(user)  # signed-in requests bypass the response cache
    views = lane_views(session, _now(), range_, hidden)
    capped = {lane: v[:limit] for lane, v in views.items()}
    ids = list({v.cve_id for vs in capped.values() for v in vs})
    rows: dict[str, Cve] = {}
    if ids:  # ONE query for the fields CveView lacks
        rows = {c.cve_id: c for c in session.scalars(select(Cve).where(Cve.cve_id.in_(ids)))}
    seen = last_seen_map(session, ids, hidden)
    out: dict[str, dict] = {}
    for lane in Lane:
        items = []
        for v in capped.get(lane, []):
            c = rows.get(v.cve_id)
            if c is not None:
                items.append(_item(c, v.recent_story_count, seen.get(c.cve_id)))
        out[lane.value] = {"total": len(views.get(lane, [])), "items": items}
    return out


def _legacy_conds(
    session: Session,
    *,
    source: str | None,
    lane: Lane | None,
    min_cvss: float | None,
    kev: bool | None,
    from_: date | None,
    to: date | None,
    kev_from: date | None,
    kev_to: date | None,
    hidden: frozenset[str] = frozenset(),
) -> list:
    """History-page params, kept until the Threats page replaces it."""
    conds = []
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
    if kev_from is not None:
        conds.append(Cve.kev_added >= kev_from)
    if kev_to is not None:  # inclusive
        conds.append(Cve.kev_added <= kev_to)
    if lane is not None:
        members = [v.cve_id for v in lane_views(session, _now(), exclude_sources=hidden)[lane]]
        conds.append(Cve.cve_id == any_(literal(members, ARRAY(String))))
    return conds


@router.get("/cves", response_model=CveListOut)
def search_cves(
    q: Annotated[str | None, Query(max_length=200)] = None,
    added: AddedKey = "any",
    status: StatusKey = "all",
    exclude_kev: bool = False,
    sev: Annotated[str | None, Query(max_length=40)] = None,
    poc: bool | None = None,
    nopatch: bool | None = None,
    due: Literal["7d"] | None = None,
    source: Literal["cisa", "vulncheck"] | None = None,
    lane: Lane | None = None,
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    kev: bool | None = None,
    from_: Annotated[date | None, Query(alias="from")] = None,
    to: date | None = None,
    kev_from: date | None = None,
    kev_to: date | None = None,
    sort: SortKey | None = None,
    page: Annotated[int, Query(ge=1, le=10000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    session: Session = SessionDep,
    user: User | None = Depends(current_user),  # gated by the router-level public_or_user
) -> dict:
    now = _now()
    hidden = restricted_sources(user)
    sev_keys = _parse_sev(sev)

    exact_id = None
    if q and CVE_ID_RE.fullmatch(q.strip().upper()):
        exact_id = q.strip().upper()

    def filters(*, with_q: bool) -> list:
        return [
            *cve_search_filters(
                now,
                added=added,
                status=status,
                exclude_kev=exclude_kev,
                sev=sev_keys,
                poc=poc,
                nopatch=nopatch,
                due=due is not None,
                q=q if with_q else None,
                hidden=hidden,
            ),
            *_legacy_conds(
                session,
                source=source,
                lane=lane,
                min_cvss=min_cvss,
                kev=kev,
                from_=from_,
                to=to,
                kev_from=kev_from,
                kev_to=kev_to,
                hidden=hidden,
            ),
        ]

    filtered_out = False
    if exact_id is not None:  # R15: an exact CVE id ignores every other filter
        conds = [Cve.cve_id == exact_id]
        if session.scalar(select(func.count()).select_from(Cve).where(*conds)):
            filtered_out = not session.scalar(
                select(func.count()).select_from(Cve).where(*conds, *filters(with_q=False))
            )
    else:
        conds = filters(with_q=True)

    if sort is None:
        sort = "kev_added" if kev is True and lane is None else "newest"
    if due is not None and sort == "newest":
        sort = "due"
    if sort == "due" and exact_id is None:  # soonest deadline first, KEV only
        conds += [Cve.kev.is_(True), Cve.kev_due.is_not(None)]
    order = cve_search_order(now, sort, status=status, hidden=hidden)

    total = session.scalar(select(func.count()).select_from(Cve).where(*conds)) or 0
    rows = session.scalars(
        select(Cve)
        .where(*conds)
        .order_by(*order)
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()
    ids = [r.cve_id for r in rows]
    counts = _recent_counts(session, ids, _loud_since(), hidden)
    seen = last_seen_map(session, ids, hidden)
    return {
        "items": [_item(r, counts.get(r.cve_id, 0), seen.get(r.cve_id)) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "exact_match": exact_id is not None,
        "exact_match_filtered_out": filtered_out,
    }


def _valid_version(v: object) -> bool:
    try:
        AffectedVersion.model_validate(v)
    except ValueError:
        return False
    return True


def _related(session: Session, c: Cve) -> list[dict]:
    """Up to 4 other CVEs: same product first, then same first CWE; kev, cvss desc, id."""
    label = product_label(c)
    groups = []
    if label:
        affected = [a for a in (c.affected or []) if isinstance(a, str)]
        if label in affected:
            groups.append(Cve.affected.contains([label]))
        else:
            product = next(
                (
                    v["product"]
                    for v in c.affected_versions or []
                    if isinstance(v, dict)
                    and isinstance(v.get("product"), str)
                    and label in (v["product"], f"{v.get('vendor')} {v['product']}")
                ),
                None,
            )
            if product:
                groups.append(Cve.affected_versions.contains([{"product": product}]))
            elif affected:  # label came from the tail of a CPE-ish entry
                groups.append(Cve.affected.contains([affected[0]]))
    cwes = [w for w in (c.cwes or []) if isinstance(w, str)]
    if cwes:
        groups.append(Cve.cwes.contains([cwes[0]]))
    out: list[Cve] = []
    for cond in groups:
        if len(out) >= 4:
            break
        rows = session.scalars(
            select(Cve)
            .where(
                cond,
                Cve.cve_id != c.cve_id,
                Cve.cve_id.not_in([r.cve_id for r in out]),
            )
            .order_by(Cve.kev.desc(), Cve.cvss.desc().nulls_last(), Cve.cve_id)
            .limit(4 - len(out))
        ).all()
        out.extend(rows)
    return [
        {
            "cve_id": r.cve_id,
            "cvss": r.cvss,
            "kev": r.kev,
            "epss_percentile": r.epss_percentile,
            "product": product_label(r),
        }
        for r in out
    ]


@router.get("/cves/{cve_id:path}", response_model=CveDetail)
def cve_detail(
    cve_id: str,
    range_: Annotated[RangeKey, Query(alias="range")] = DEFAULT_RANGE,
    session: Session = SessionDep,
    user: User | None = Depends(current_user),  # gated by the router-level public_or_user
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
    counts = _recent_counts(session, [cve_id], _loud_since(), hidden)
    seen = last_seen_map(session, [cve_id], hidden)
    events = session.execute(
        select(CveEvent.kind, CveEvent.occurred_at, CveEvent.source, CveEvent.detail)
        .where(CveEvent.cve_id == cve_id, CveEvent.source.not_in(hidden))
        .order_by(CveEvent.occurred_at, CveEvent.id)
        .limit(100)
    ).all()
    country = GeoEvent.country_code
    geo_top = session.execute(
        select(country, func.count().label("events"))
        .where(
            GeoEvent.cve_id == cve_id,
            GeoEvent.observed_at >= range_start(_now(), range_),
            country.is_not(None),
        )
        .group_by(country)
        .order_by(func.count().desc(), country)
        .limit(3)
    ).all()
    references = [
        CveReferenceOut(
            url=r["url"],
            tags=[t for t in (r.get("tags") or []) if isinstance(t, str)],
        )
        for r in (c.references or [])
        if isinstance(r, dict) and isinstance(r.get("url"), str)
    ]
    seen_urls = {r.url for r in references}
    for ev in events:
        url = (ev.detail or {}).get("url") if ev.kind == "poc_published" else None
        try:
            url = validate_http_url(url)
        except ValueError:
            continue
        if url not in seen_urls:
            seen_urls.add(url)
            references.append(CveReferenceOut(url=url, tags=["Exploit"]))
    return {
        **_item(c, counts.get(cve_id, 0), seen.get(cve_id)),
        "epss": c.epss,
        "affected": c.affected,
        "kev_name": c.kev_name,
        "kev_action": c.kev_action,
        "kev_due": c.kev_due,
        "kev_ransomware": c.kev_ransomware,
        "kev_notes": c.kev_notes,
        "cvss_vector": c.cvss_vector,
        "cvss_severity": c.cvss_severity,
        "cwes": [w for w in (c.cwes or []) if isinstance(w, str)],
        "references": references,
        "last_modified": c.last_modified,
        "stories": [StoryRef(**r._asdict()) for r in stories],
        "geo_events": [GeoEventOut(**r._asdict()) for r in geo],
        "events": [CveEventOut(**r._asdict()) for r in events],
        "affected_versions": [
            AffectedVersionOut.model_validate(v)
            for v in (c.affected_versions or [])
            if _valid_version(v)
        ],
        "related": [RelatedCve(**r) for r in _related(session, c)],
        "geo_top": [GeoTop(country_code=r[0], events=r[1]) for r in geo_top],
        "updated_at": c.updated_at,
    }


@router.get("/velocity", response_model=VelocityOut)
def velocity(
    days: Annotated[int, Query(ge=1, le=30)] = 30, session: Session = SessionDep
) -> dict:
    return cve_velocity(session, _now(), days=days)


@router.get("/summary", response_model=SummaryOut)
def summary(
    range_: Annotated[RangeKey, Query(alias="range")] = DEFAULT_RANGE,
    session: Session = SessionDep,
) -> dict:
    return summary_counts(session, _now(), range_)


@router.get("/volume", response_model=VolumeOut)
def volume(
    range_: Annotated[RangeKey, Query(alias="range")] = DEFAULT_RANGE,
    session: Session = SessionDep,
) -> dict:
    return cve_volume(session, _now(), range_)


@router.get("/geo", response_model=list[GeoSummaryItem])
def geo(
    window_hours: Annotated[int, Query(ge=1, le=168)] = 24,
    range_: Annotated[RangeKey | None, Query(alias="range")] = None,
    session: Session = SessionDep,
) -> list[dict]:
    if range_ is not None:  # range wins over window_hours
        window_hours = RANGE_DAYS[range_] * 24
    return geo_summary(session, _now(), window_hours=window_hours)


@router.get("/geo/{cc}", response_model=CountryActivityOut)
def geo_country(
    cc: Annotated[str, Path(pattern="^[A-Z]{2}$")],
    window_hours: Annotated[int, Query(ge=1, le=168)] = 24,
    range_: Annotated[RangeKey | None, Query(alias="range")] = None,
    session: Session = SessionDep,
    user: User | None = Depends(current_user),  # gated by the router-level public_or_user
) -> dict:
    if range_ is not None:  # range wins over window_hours
        window_hours = RANGE_DAYS[range_] * 24
    # Anonymous callers get counts only (events=None) so the cached body never
    # carries individual records; signed-in requests bypass the cache.
    return country_activity(
        session, _now(), cc, window_hours=window_hours, include_events=user is not None
    )


@router.get("/stories/loud", response_model=list[LoudStory])
def stories_loud(
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    range_: Annotated[RangeKey, Query(alias="range")] = DEFAULT_RANGE,
    session: Session = SessionDep,
    user: User | None = Depends(current_user),  # gated by the router-level public_or_user
) -> list[dict]:
    return loud_stories(
        session, _now(), limit=limit, rng=range_, exclude_sources=restricted_sources(user)
    )


@router.get("/stories", response_model=StoryListOut)
def stories_search(
    q: Annotated[str | None, Query(max_length=200)] = None,
    source: Annotated[str | None, Query(max_length=64)] = None,
    kind: Literal["news", "ransomware"] = "news",
    from_: Annotated[date | None, Query(alias="from")] = None,
    to: date | None = None,
    added: AddedKey = "any",
    page: Annotated[int, Query(ge=1, le=10000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    session: Session = SessionDep,
    user: User | None = Depends(current_user),  # gated by the router-level public_or_user
) -> dict:
    start = datetime.combine(from_, time.min, tzinfo=UTC) if from_ is not None else None
    if added != "any":  # story published within the window; combines with `from` (later wins)
        window = _now() - timedelta(days=ADDED_DAYS[added])
        start = window if start is None else max(start, window)
    end = None
    if to is not None and to < date.max:
        end = datetime.combine(to + timedelta(days=1), time.min, tzinfo=UTC)
    hidden = restricted_sources(user)
    # news excludes ransomware sources; ransomware keeps only them. For anonymous callers the
    # restricted filter still applies in SQL, so kind=ransomware yields no rows and a zero total.
    items, total = search_stories(
        session,
        q=q,
        source=source,
        start=start,
        end=end,
        page=page,
        page_size=page_size,
        exclude_sources=hidden if kind == "ransomware" else hidden | RESTRICTED_SOURCES,
        include_sources=RESTRICTED_SOURCES if kind == "ransomware" else frozenset(),
    )
    return {"items": items, "page": page, "page_size": page_size, "total": total}


@router.get("/story", response_model=StoryDetailOut)
def story_lookup(
    url: Annotated[str, Query(max_length=2048)],
    session: Session = SessionDep,
    user: User | None = Depends(current_user),  # gated by the router-level public_or_user
):
    found = story_detail(session, url, restricted_sources(user))
    if found is None:  # missing and restricted-for-anonymous share one response
        return JSONResponse({"error": "not_found"}, status_code=404)
    return found
