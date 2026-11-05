from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cvenom.config import get_settings
from cvenom.models import Cve
from cvenom.schemas import NormalizedCve

engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Fields overwritten only when the incoming value is not None.
_MERGE_FIELDS = (
    "published", "cvss", "epss", "epss_percentile", "kev_added", "kev_source",
    "patch_available", "summary",
)


def upsert_cve(session: Session, data: NormalizedCve) -> Cve:
    """Insert or merge a CVE by id.

    Only non-null incoming fields overwrite; kev and poc_badge are sticky
    (never True to False); affected is unioned, preserving order.
    """
    row = session.get(Cve, data.cve_id)
    if row is None:
        row = Cve(cve_id=data.cve_id, kev=False, poc_badge=False, affected=[], summary="")
        session.add(row)
    for field in _MERGE_FIELDS:
        value = getattr(data, field)
        if value is not None and value != "":
            setattr(row, field, value)
    row.kev = bool(row.kev) or data.kev
    row.poc_badge = bool(row.poc_badge) or data.poc_badge
    existing = list(row.affected or [])
    row.affected = existing + [a for a in dict.fromkeys(data.affected) if a not in existing]
    session.flush()
    return row
