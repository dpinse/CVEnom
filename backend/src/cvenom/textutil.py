import hashlib
import re

import bleach
from sqlalchemy import select
from sqlalchemy.orm import Session

from cvenom.models import Story

_WS = re.compile(r"\s+")
_SEP = "\x1f"  # unit separator: keeps (title, summary) pairs unambiguous
# bleach strips script/style tags but keeps their text, so drop those blocks entirely first.
_SCRIPT_BLOCK = re.compile(
    r"<(script|style)\b[^>]*>.*?(?:</\1\s*>|$)", re.IGNORECASE | re.DOTALL
)


def _normalize(text: str) -> str:
    return _WS.sub(" ", text).strip().casefold()


def content_hash(title: str, summary: str) -> str:
    """Stable sha256 hex digest of the normalized title and summary (order-sensitive)."""
    payload = _normalize(title) + _SEP + _normalize(summary)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sanitize_text(raw: str | None) -> str:
    """Strip all HTML and script content to plain text and collapse whitespace.

    This is an XSS defense on ingest: tags are removed entirely (not escaped).
    """
    if not raw:
        return ""
    without_blocks = _SCRIPT_BLOCK.sub(" ", raw)
    stripped = bleach.clean(without_blocks, tags=[], attributes={}, strip=True)
    return _WS.sub(" ", stripped).strip()


def find_existing_story(session: Session, url: str, content_hash: str) -> Story | None:
    """Return the story matching ``url``, falling back to ``content_hash``."""
    by_url = session.scalars(select(Story).where(Story.url == url)).first()
    if by_url is not None:
        return by_url
    return session.scalars(
        select(Story).where(Story.content_hash == content_hash)
    ).first()
