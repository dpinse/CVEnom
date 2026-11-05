from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from cvenom.config import get_settings
from cvenom.models import Cve
from cvenom.schemas import NormalizedCve


@lru_cache
def get_engine() -> Engine:
    return create_engine(get_settings().database_url, pool_pre_ping=True)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Fields overwritten only when the incoming value is not None.
_MERGE_FIELDS = ("published", "cvss", "epss", "epss_percentile", "summary")

# kev_source with precedence: an incoming non-CISA source never replaces CISA.
_KEV_SOURCE_CISA = "cisa"


def upsert_cve(session: Session, data: NormalizedCve) -> Cve:
    """Insert or merge a CVE by id.

    Only non-null incoming fields overwrite; kev, poc_badge and patch_available
    are sticky (never True to False); kev_added keeps the EARLIEST date seen;
    kev_source "cisa" is never replaced by another source; affected is
    unioned, preserving order.
    """
    row = session.get(Cve, data.cve_id)
    if row is None:
        row = Cve(cve_id=data.cve_id, kev=False, poc_badge=False, affected=[], summary="")
        session.add(row)
    for field in _MERGE_FIELDS:
        value = getattr(data, field)
        if value is not None and value != "":
            setattr(row, field, value)
    if data.kev_added is not None:
        row.kev_added = data.kev_added if row.kev_added is None else min(row.kev_added, data.kev_added)
    if data.kev_source and not (
        row.kev_source == _KEV_SOURCE_CISA and data.kev_source != _KEV_SOURCE_CISA
    ):
        row.kev_source = data.kev_source
    if data.patch_available is not None:
        # Sticky True: one source saying "fixed" is not undone by a later "no fix".
        row.patch_available = row.patch_available is True or data.patch_available
    row.kev = bool(row.kev) or data.kev
    row.poc_badge = bool(row.poc_badge) or data.poc_badge
    existing = list(row.affected or [])
    row.affected = existing + [a for a in dict.fromkeys(data.affected) if a not in existing]
    session.flush()
    return row
