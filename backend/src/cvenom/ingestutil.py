"""Small ingest helpers shared by ``pipeline`` and ``timeline`` (keeps them import-cycle free)."""

import math
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from cvenom.models import Cve
from cvenom.textutil import sanitize_text

_ID_CHUNK = 1000
_DETAILS_MAX_DEPTH = 4


def _in_chunks(session: Session, entity, ids: Iterable[str], *conditions) -> list:
    """SELECT ``entity`` for the ``cve`` rows whose id is in ``ids`` (and ``conditions``).

    Chunked ``IN`` lists keep the statement count O(len(ids) / _ID_CHUNK).
    """
    unique = list(dict.fromkeys(ids))
    found: list = []
    for i in range(0, len(unique), _ID_CHUNK):
        chunk = unique[i : i + _ID_CHUNK]
        found.extend(session.scalars(select(entity).where(Cve.cve_id.in_(chunk), *conditions)))
    return found


def _sanitize_details(value, depth: int = 0):
    """Sanitize every string inside a details structure (keys coerced to str, depth-limited)."""
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, float) and not math.isfinite(value):
        return None  # Postgres JSONB rejects NaN/Infinity
    if depth >= _DETAILS_MAX_DEPTH:
        return None if isinstance(value, (dict, list, tuple)) else value
    if isinstance(value, dict):
        return {sanitize_text(str(k)): _sanitize_details(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_details(v, depth + 1) for v in value]
    return value
