"""Ingestion pipeline and lane views.

``ingest`` does not commit: it flushes and the caller owns the transaction.
"""

from datetime import datetime, timedelta

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cvenom.collectors.base import CollectorResult
from cvenom.config import get_settings
from cvenom.db import upsert_cve
from cvenom.extract import extract_cve_ids, link_story
from cvenom.models import Cve, Story, StoryCveLink
from cvenom.schemas import NormalizedCve
from cvenom.scoring import CveView, Lane, heat_rank, lanes_for_cve
from cvenom.textutil import content_hash, find_existing_story, sanitize_text


def _upsert_with_retry(session: Session, data: NormalizedCve) -> None:
    """Upsert inside a SAVEPOINT; retry once if a concurrent insert wins the race."""
    for attempt in (1, 2):
        try:
            with session.begin_nested():
                upsert_cve(session, data)
            return
        except IntegrityError:
            if attempt == 2:
                raise


def ingest(session: Session, result: CollectorResult, *, enrich_only: bool = False) -> list[dict]:
    """Persist a collector result. Returns ``result.events`` unchanged."""
    for cve in result.cves:
        if enrich_only and session.get(Cve, cve.cve_id) is None:
            continue
        _upsert_with_retry(session, cve.model_copy(update={"summary": sanitize_text(cve.summary)}))

    for story in result.stories:
        cve_ids = extract_cve_ids(f"{story.title} {story.summary}")  # raw text
        title = sanitize_text(story.title)
        summary = sanitize_text(story.summary)
        digest = content_hash(title, summary)
        if find_existing_story(session, story.url, digest) is not None:
            continue
        row = Story(
            url=story.url,
            content_hash=digest,
            source=story.source,
            title=title,
            summary=summary,
            published=story.published,
        )
        session.add(row)
        session.flush()
        link_story(session, row, cve_ids)

    session.flush()
    return result.events


def lane_views(session: Session, now: datetime) -> dict[Lane, list[CveView]]:
    cfg = get_settings()
    loud_cutoff = now - timedelta(hours=cfg.loud_window_hours)
    fresh_cutoff = now - timedelta(hours=cfg.fresh_window_hours)

    recent_link = (
        select(StoryCveLink.cve_id)
        .join(Story, Story.id == StoryCveLink.story_id)
        .where(StoryCveLink.cve_id == Cve.cve_id, Story.published >= loud_cutoff)
    )
    candidates = select(Cve).where(
        or_(
            Cve.kev.is_(True),
            Cve.epss_percentile >= cfg.epss_percentile_threshold,
            and_(Cve.cvss >= cfg.fresh_cvss_floor, Cve.published >= fresh_cutoff),
            exists(recent_link),
        )
    )
    rows = session.scalars(candidates).all()

    counts: dict[str, int] = {}
    if rows:
        counts = dict(
            session.execute(
                select(StoryCveLink.cve_id, func.count())
                .join(Story, Story.id == StoryCveLink.story_id)
                .where(
                    StoryCveLink.cve_id.in_([r.cve_id for r in rows]),
                    Story.published >= loud_cutoff,
                )
                .group_by(StoryCveLink.cve_id)
            ).all()
        )

    lanes: dict[Lane, list[CveView]] = {lane: [] for lane in Lane}
    for r in rows:
        view = CveView(
            cve_id=r.cve_id,
            published=r.published,
            cvss=r.cvss,
            epss_percentile=r.epss_percentile,
            kev=r.kev,
            recent_story_count=counts.get(r.cve_id, 0),
            patch_available=r.patch_available,
            poc_badge=r.poc_badge,
        )
        for lane in lanes_for_cve(view, now, cfg):
            lanes[lane].append(view)
    for views in lanes.values():
        views.sort(key=lambda v: heat_rank(v, now, cfg), reverse=True)
    return lanes
