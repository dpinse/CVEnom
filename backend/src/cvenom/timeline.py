"""CVE timeline events: derivation at ingest time and idempotent persistence."""

import json
import logging
from collections.abc import Iterable
from datetime import datetime, time, timezone
from urllib.parse import urlsplit

from pydantic import ValidationError
from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from cvenom.config import Settings
from cvenom.ingestutil import _in_chunks, _sanitize_details
from cvenom.models import Cve, CveEvent
from cvenom.schemas import NormalizedCve, NormalizedCveEvent
from cvenom.textutil import sanitize_text

log = logging.getLogger(__name__)

SOURCE_LABELS = {
    "nvd": "NVD",
    "cisa_kev": "CISA KEV",
    "vulncheck_kev": "VulnCheck KEV",
    "epss": "FIRST EPSS",
    "osv": "OSV",
    "exploitdb": "Exploit-DB",
}
KEV_SOURCE_LABELS = {"cisa": "CISA KEV", "vulncheck": "VulnCheck KEV"}
MAX_EVENT_DETAIL_BYTES = 2048
_CHUNK = 500
_CONSTRAINT = "uq_cve_event_cve_kind_source"
_NUCLEI_PREFIX = "/projectdiscovery/nuclei-templates/"


def is_nuclei_reference(url: str) -> bool:
    """True iff ``url`` points into the projectdiscovery/nuclei-templates repo on github.com."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    return (host or "").lower() == "github.com" and parts.path.lower().startswith(_NUCLEI_PREFIX)


def derived_events(
    cves: Iterable[NormalizedCve], *, collector: str | None, now: datetime, cfg: Settings
) -> list[NormalizedCveEvent]:
    """Timeline events implied by the CVE records a collector just delivered."""
    out: list[NormalizedCveEvent] = []
    published_source = SOURCE_LABELS.get(collector, collector or "CVEnom")
    for cve in cves:

        def add(kind, occurred_at, source, detail=None, cve=cve):
            try:
                out.append(NormalizedCveEvent(
                    cve_id=cve.cve_id, kind=kind, occurred_at=occurred_at, source=source,
                    detail=detail or {},
                ))
            except ValidationError as exc:  # one bad value must not abort the batch
                log.warning("skipping %s event for %s: %s", kind, cve.cve_id, exc)

        if cve.published is not None:
            add("published", cve.published, published_source)
        if cve.kev and cve.kev_added is not None:
            add("kev_added", datetime.combine(cve.kev_added, time.min, tzinfo=timezone.utc),
                KEV_SOURCE_LABELS.get(cve.kev_source, "KEV"))
        if (cve.epss_percentile is not None
                and cve.epss_percentile >= cfg.epss_percentile_threshold):
            add("epss_crossed", now, "FIRST EPSS", {"percentile": cve.epss_percentile})
        if collector == "nvd" and cve.last_modified is not None:
            add("nvd_modified", cve.last_modified, "NVD")
        for ref in cve.references or []:
            if is_nuclei_reference(ref.url):
                add("detection", now, "Nuclei templates", {"url": ref.url})
                break
    return out


def _clean_detail(detail: dict) -> dict:
    clean = _sanitize_details(detail)
    if len(json.dumps(clean, default=str).encode("utf-8")) > MAX_EVENT_DETAIL_BYTES:
        return {}
    return clean


def insert_cve_events(session: Session, events: list[NormalizedCveEvent]) -> int:
    """Persist events idempotently on (cve_id, kind, source); returns rows written.

    Unknown CVEs are dropped. The first write wins, except ``nvd_modified``
    (moves forward only) and ``first_news`` (the earliest story wins).
    """
    if not events:
        return 0
    known = set(_in_chunks(session, Cve.cve_id, (e.cve_id for e in events)))
    rows: dict[tuple, dict] = {}
    for e in events:
        if e.cve_id not in known:
            continue
        key = (e.cve_id, e.kind, sanitize_text(e.source))
        row = {
            "cve_id": e.cve_id, "kind": e.kind, "occurred_at": e.occurred_at,
            "source": key[2], "detail": _clean_detail(e.detail),
        }
        prev = rows.get(key)
        if prev is None:
            rows[key] = row
        elif e.kind == "nvd_modified":
            if row["occurred_at"] > prev["occurred_at"]:
                rows[key] = row
        elif row["occurred_at"] < prev["occurred_at"]:
            rows[key] = row

    groups: dict[str, list[dict]] = {"nothing": [], "nvd_modified": [], "first_news": []}
    for row in rows.values():
        groups[row["kind"] if row["kind"] in groups else "nothing"].append(row)

    written = 0
    for name, values in groups.items():
        for i in range(0, len(values), _CHUNK):
            stmt = pg_insert(CveEvent).values(values[i : i + _CHUNK])
            if name == "nothing":
                stmt = stmt.on_conflict_do_nothing(constraint=_CONSTRAINT)
            elif name == "nvd_modified":
                stmt = stmt.on_conflict_do_update(
                    constraint=_CONSTRAINT,
                    set_={"occurred_at": func.greatest(CveEvent.occurred_at, stmt.excluded.occurred_at)},
                )
            else:
                earlier = stmt.excluded.occurred_at < CveEvent.occurred_at
                stmt = stmt.on_conflict_do_update(
                    constraint=_CONSTRAINT,
                    set_={
                        "occurred_at": func.least(CveEvent.occurred_at, stmt.excluded.occurred_at),
                        # keep the earlier story's detail
                        "detail": case((earlier, stmt.excluded.detail), else_=CveEvent.detail),
                    },
                )
            written += len(session.execute(stmt.returning(CveEvent.id)).all())
    return written
