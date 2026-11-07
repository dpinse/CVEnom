"""Ingestion pipeline and lane views.

``ingest`` does not commit: it flushes and the caller owns the transaction.
"""

import logging
import math
from collections.abc import Callable
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import and_, delete, exists, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cvenom.collectors.base import CollectorResult
from cvenom.config import get_settings
from cvenom.db import upsert_cve
from cvenom.extract import extract_cve_ids, link_story
from cvenom.ingestutil import _DETAILS_MAX_DEPTH, _ID_CHUNK, _in_chunks, _sanitize_details
from cvenom.models import AlertEvent, Cve, GeoEvent, Story, StoryCveLink
from cvenom.schemas import (
    CVE_ID_RE,
    MAX_AFFECTED_FIELD_LEN,
    MAX_CVSS_VECTOR_LEN,
    AffectedVersion,
    CveReference,
    NormalizedCve,
    NormalizedCveEvent,
    NormalizedGeoEvent,
    NormalizedStory,
)
from cvenom.ranges import DEFAULT_RANGE, RangeKey, range_start, range_start_date
from cvenom.scoring import CveView, Lane, heat_rank, lanes_for_cve, priority_key
from cvenom.textutil import content_hash, find_existing_story, sanitize_text
from cvenom.timeline import derived_events, insert_cve_events

log = logging.getLogger(__name__)

_UNIQUE_VIOLATION = "23505"


def _is_unique_violation(exc: IntegrityError) -> bool:
    return getattr(exc.orig, "sqlstate", None) == _UNIQUE_VIOLATION


def _retry_unique(session: Session, work: Callable[[], None]) -> None:
    """Run ``work`` in a SAVEPOINT; retry once on a unique violation (concurrent insert).

    Any other IntegrityError (FK, NOT NULL) re-raises immediately.
    """
    for attempt in (1, 2):
        try:
            with session.begin_nested():
                work()
            return
        except IntegrityError as exc:
            if attempt == 2 or not _is_unique_violation(exc):
                raise


def _ingest_story(session: Session, story: NormalizedStory) -> None:
    cve_ids = extract_cve_ids(f"{story.title} {story.summary}")  # raw text
    title = sanitize_text(story.title)
    summary = sanitize_text(story.summary)
    digest = content_hash(title, summary)
    if find_existing_story(session, story.url, digest) is not None:
        return
    row = Story(
        url=story.url,
        content_hash=digest,
        source=story.source,
        title=title,
        summary=summary,
        published=story.published,
        details=_sanitize_details(story.details),
    )
    session.add(row)
    session.flush()
    link_story(session, row, cve_ids)
    if cve_ids:
        # NormalizedCveEvent.source is capped at 64 chars and rejects control characters;
        # same prefix as the migration backfill (left(source, 64)).
        event_source = sanitize_text(story.source)[:64] or "unknown"
        insert_cve_events(session, [
            NormalizedCveEvent(
                cve_id=cve_id, kind="first_news", occurred_at=story.published,
                source=event_source, detail={"title": title, "url": story.url},
            )
            for cve_id in sorted(cve_ids)
        ])


def _drop_known_kev_events(session: Session, events: list[dict]) -> list[dict]:
    """Drop ``kev_added`` events for CVEs that are ALREADY kev=True in the DB.

    The sticky DB kev flag acts as a second seen-set: a CVE listed by both CISA
    and VulnCheck (or re-emitted after lost/corrupt collector state) alerts once.
    Must run before the result's CVEs are upserted.

    Final rule for a ``kev_added`` event on an already-KEV CVE:
      * VulnCheck (or any non-CISA source): always dropped.
      * CISA: passes if and only if ``cve.kev_alerted_at IS NULL``, i.e. no
        ``kev_added`` alert event was ever persisted for the CVE (VulnCheck may
        have flagged it silently via its first-run baseline or the recency gate
        in ``collectors/seenstate.py``). ``persist_events`` stamps
        ``kev_alerted_at``, so a CVE alerts once, from whichever source is first.
    The CISA collector's own seen-set and 14-day recency gate still apply
    upstream: only a listing new to CISA's seen-set and added within
    ``kev_alert_max_age_days`` (or with an unknown date) emits at all, so very
    old CISA additions never alert.
    """
    kev_ids = [e.get("cve_id") for e in events if e.get("type") == "kev_added"]
    if not kev_ids:
        return events
    already = set(_in_chunks(session, Cve.cve_id, kev_ids, Cve.kev.is_(True)))
    never_alerted = set(
        _in_chunks(session, Cve.cve_id, kev_ids, Cve.kev.is_(True), Cve.kev_alerted_at.is_(None))
    )

    def dropped(e: dict) -> bool:
        if e.get("type") != "kev_added" or e.get("cve_id") not in already:
            return False
        return not (e.get("source") == "cisa" and e.get("cve_id") in never_alerted)

    return [e for e in events if not dropped(e)]


def _sanitize_opt(value: str | None) -> str | None:
    return None if value is None else sanitize_text(value)


def _sanitized_references(refs: list[CveReference] | None) -> list[CveReference] | None:
    if refs is None:
        return None
    out = []
    for ref in refs:
        url = sanitize_text(ref.url)
        if url:
            tags = [clean for t in ref.tags if (clean := sanitize_text(t))]
            # model_construct: the url was validated at the boundary; it is now entity-escaped
            # text for a JSON column (links decode it once on render).
            out.append(CveReference.model_construct(url=url, tags=tags))
    return out


def _sanitized_vector(value: str | None) -> str | None:
    # Entity-escaping can grow the text past the String(255) column: drop it instead.
    clean = _sanitize_opt(value)
    return None if clean is None or len(clean) > MAX_CVSS_VECTOR_LEN else clean


def _sanitized_versions(entries: list[AffectedVersion] | None) -> list[AffectedVersion] | None:
    if entries is None:
        return None
    out = []
    for entry in entries:
        clean = {k: (None if v is None else sanitize_text(v)) for k, v in entry.model_dump().items()}
        # Entity-escaping can grow a string past 128: drop the entry rather than truncate it.
        if not clean["product"] or any(len(v) > MAX_AFFECTED_FIELD_LEN for v in clean.values() if v):
            continue
        out.append(AffectedVersion.model_construct(**{k: (v or None) for k, v in clean.items()}))
    return out


def _sanitized(cve: NormalizedCve) -> NormalizedCve:
    return cve.model_copy(update={
        "summary": sanitize_text(cve.summary),
        "affected": [clean for a in cve.affected if (clean := sanitize_text(a))],
        "kev_name": _sanitize_opt(cve.kev_name),
        "kev_action": _sanitize_opt(cve.kev_action),
        "kev_notes": _sanitize_opt(cve.kev_notes),
        "cvss_vector": _sanitized_vector(cve.cvss_vector),
        "cwes": None if cve.cwes is None else [clean for c in cve.cwes if (clean := sanitize_text(c))],
        "references": _sanitized_references(cve.references),
        "affected_versions": _sanitized_versions(cve.affected_versions),
    })


_GEO_CHUNK = 500
_GEO_UPDATE_COLS = (
    "observed_at", "magnitude", "label", "details", "kind",
    "country_code", "asn", "cve_id", "story_url",
)


def _upsert_geo_events(session: Session, events: list[NormalizedGeoEvent]) -> None:
    """Chunked ON CONFLICT upsert keyed on (source, external_id); first_seen is kept.

    A chunk may not repeat a key (Postgres would reject the second touch), so
    duplicates collapse to the last occurrence first.
    """
    by_key = {}
    for e in events:
        by_key[(e.source, e.external_id)] = {
            "source": e.source,
            "external_id": e.external_id,
            "kind": e.kind,
            "country_code": e.country_code,
            "asn": e.asn,
            "observed_at": e.observed_at,
            "magnitude": e.magnitude,
            "label": sanitize_text(e.label) if e.label is not None else None,
            "cve_id": e.cve_id,
            "story_url": e.story_url,
            "details": _sanitize_details(e.details),
        }
    values = list(by_key.values())
    for i in range(0, len(values), _GEO_CHUNK):
        stmt = pg_insert(GeoEvent).values(values[i : i + _GEO_CHUNK])
        stmt = stmt.on_conflict_do_update(
            index_elements=["source", "external_id"],
            set_={c: getattr(stmt.excluded, c) for c in _GEO_UPDATE_COLS},
        )
        session.execute(stmt)


def purge_old_geo_events(session: Session, now: datetime, *, days: int) -> int:
    """Delete geo events observed before ``now - days``; returns the row count. No commit."""
    now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    cutoff = now - timedelta(days=days)
    return session.execute(delete(GeoEvent).where(GeoEvent.observed_at < cutoff)).rowcount


def ingest(session: Session, result: CollectorResult, *, enrich_only: bool = False,
           collector: str | None = None) -> list[dict]:
    """Persist a collector result and return its events.

    ``kev_added`` events for CVEs already KEV in the DB are dropped; all other
    events pass through unchanged. enrich_only skips unknown CVEs and all
    stories (so nothing can stub-create CVEs).
    """
    events = _drop_known_kev_events(session, result.events)

    if enrich_only:
        # Prefetch the existing rows in chunks: unknown ids are skipped without a
        # query, and upsert_cve's session.get hits the identity map (the dict keeps
        # the rows strongly referenced). No insert can happen on this path, so no
        # SAVEPOINT/retry is needed.
        existing = {r.cve_id: r for r in _in_chunks(session, Cve, (c.cve_id for c in result.cves))}
        upserted = [c for c in result.cves if c.cve_id in existing]
        for cve in upserted:
            upsert_cve(session, _sanitized(cve))
    else:
        upserted = list(result.cves)
        for cve in upserted:
            data = _sanitized(cve)
            _retry_unique(session, lambda data=data: upsert_cve(session, data))
        for story in result.stories:
            _retry_unique(session, lambda story=story: _ingest_story(session, story))

    cve_events = derived_events(
        upserted, collector=collector, now=datetime.now(timezone.utc), cfg=get_settings()
    ) + list(result.cve_events)
    if cve_events:
        insert_cve_events(session, cve_events)

    # Geo events never create CVE rows (cve_id is a plain reference), so they are
    # processed regardless of enrich_only.
    if result.geo_events:
        _upsert_geo_events(session, result.geo_events)

    session.flush()
    return events


def _json_safe(value, depth: int = 0):
    """JSON/JSONB-safe copy: dates -> ISO strings, NUL stripped, NaN/Inf -> None."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if depth >= _DETAILS_MAX_DEPTH + 4:
        return None
    if isinstance(value, dict):
        return {str(k).replace("\x00", ""): _json_safe(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v, depth + 1) for v in value]
    return str(value).replace("\x00", "")


def persist_events(session: Session, events: list[dict], *, source_default: str) -> int:
    """Write events as AlertEvent outbox rows in the caller's transaction (no commit).

    Malformed events are skipped with a WARNING, never raised. Events repeating a
    (type, cve_id) pair within one call are written once (events without a cve_id are never deduped). Returns the count added.
    """
    seen: set[tuple[str, str | None]] = set()
    added = 0
    kev_alerted: set[str] = set()
    for e in events:
        etype = e.get("type") if isinstance(e, dict) else None
        cve_id = e.get("cve_id") if isinstance(e, dict) else None
        source = (e.get("source") or source_default) if isinstance(e, dict) else None
        if not (
            isinstance(etype, str) and 0 < len(etype) <= 64
            and (cve_id is None or (isinstance(cve_id, str) and CVE_ID_RE.fullmatch(cve_id)))
            and isinstance(source, str) and 0 < len(source) <= 64
        ):
            log.warning("skipping invalid alert event (type=%r)", etype if isinstance(etype, str) else None)
            continue
        if "\x00" in etype or "\x00" in source:
            log.warning("skipping alert event with NUL in type/source")
            continue
        if cve_id is not None:
            key = (etype, cve_id)
            if key in seen:
                continue
            seen.add(key)
        payload = {k: v for k, v in e.items() if k not in ("type", "cve_id", "source")}
        session.add(AlertEvent(type=etype, cve_id=cve_id, source=source, payload=_json_safe(payload)))
        added += 1
        if etype == "kev_added" and cve_id is not None:
            kev_alerted.add(cve_id)
    if added:
        session.flush()
    if kev_alerted:
        # Same transaction as the events: stamp the first kev_added alert per CVE.
        for i in range(0, len(kev_alerted), _ID_CHUNK):
            session.execute(
                update(Cve)
                .where(
                    Cve.cve_id.in_(list(kev_alerted)[i : i + _ID_CHUNK]),
                    Cve.kev_alerted_at.is_(None),
                )
                .values(kev_alerted_at=func.now())
                .execution_options(synchronize_session=False)
            )
    return added


def lane_views(
    session: Session,
    now: datetime,
    rng: RangeKey = DEFAULT_RANGE,
    exclude_sources: frozenset[str] = frozenset(),
) -> dict[Lane, list[CveView]]:
    cfg = get_settings()
    now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    loud_cutoff = fresh_cutoff = range_start(now, rng)
    kev_cutoff_date = range_start_date(now, rng)
    likely_cutoff = now - timedelta(days=cfg.likely_window_days)

    recent_link = (
        select(StoryCveLink.cve_id)
        .join(Story, Story.id == StoryCveLink.story_id)
        .where(
            StoryCveLink.cve_id == Cve.cve_id,
            Story.published >= loud_cutoff,
            Story.source.not_in(exclude_sources),
        )
    )
    candidates = select(Cve).where(
        or_(
            and_(Cve.kev.is_(True), Cve.kev_added >= kev_cutoff_date),
            and_(
                Cve.kev.is_not(True),
                Cve.epss_percentile >= cfg.epss_percentile_threshold,
                Cve.published >= likely_cutoff,
            ),
            and_(
                Cve.kev.is_not(True),
                Cve.cvss >= cfg.fresh_cvss_floor,
                Cve.published >= fresh_cutoff,
            ),
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
                    Story.source.not_in(exclude_sources),
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
            kev_added=r.kev_added,
            kev_ransomware=r.kev_ransomware,
        )
        for lane in lanes_for_cve(view, now, cfg, rng):
            lanes[lane].append(view)
    for lane, views in lanes.items():
        if lane is Lane.EXPLOITED:
            views.sort(key=priority_key)
        else:
            views.sort(key=lambda v: (-heat_rank(v, now, cfg), v.cve_id))
    return lanes
