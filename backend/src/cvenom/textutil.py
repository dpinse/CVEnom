"""Ingest text utilities.

``sanitize_text`` output is HTML-entity-escaped plain text: no tags survive, and
no tag-initiating ``<`` is left in the output. It is safe to store. Renderers
decode it once into a text node (React escapes on render), so text such as
``5 < 6`` is stored as ``5 &lt; 6``.
"""

import hashlib
import html
import re

import bleach
from sqlalchemy import select
from sqlalchemy.orm import Session

from cvenom.models import Story

_WS = re.compile(r"\s+")
_SEP = "\x1f"  # unit separator: keeps (title, summary) pairs unambiguous
# Drop CLOSED script/style elements together with their contents (bleach would keep
# the text). An unclosed <script>/<style> is left for bleach, which strips the tag
# token and escapes the rest, so the text after it is never silently truncated.
_SCRIPT_BLOCK = re.compile(
    r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL
)
_MAX_DECODE_PASSES = 5


def _normalize(text: str) -> str:
    return _WS.sub(" ", text).strip().casefold()


def content_hash(title: str, summary: str) -> str:
    """Stable sha256 hex digest of the normalized title and summary (order-sensitive)."""
    payload = _normalize(title) + _SEP + _normalize(summary)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _decode_to_fixed_point(text: str) -> str | None:
    """Decode HTML entities until stable (defeats multi-level encoding).

    Returns None if no fixed point is reached within the pass cap.
    """
    for _ in range(_MAX_DECODE_PASSES):
        decoded = html.unescape(text)
        if decoded == text:
            return text
        text = decoded
    return None


def sanitize_text(raw: str | None) -> str:
    """Return entity-escaped plain text with all tags and script/style content removed.

    Steps: decode the input to a fixed point, drop script/style blocks, strip all
    tags with bleach (keeping its escaped output), then collapse whitespace.
    The result is never decoded again, so it cannot re-introduce markup.
    """
    if not raw:
        return ""
    decoded = _decode_to_fixed_point(raw)
    if decoded is None:
        # Pathological nesting: fail closed rather than store a partially cleaned value.
        return ""
    without_blocks = _SCRIPT_BLOCK.sub(" ", decoded)
    escaped = bleach.clean(without_blocks, tags=[], attributes={}, strip=True)
    return _WS.sub(" ", escaped).strip()


def find_existing_story(session: Session, url: str, content_hash: str) -> Story | None:
    """Return the story matching ``url``, falling back to ``content_hash``."""
    by_url = session.scalars(select(Story).where(Story.url == url)).first()
    if by_url is not None:
        return by_url
    return session.scalars(
        select(Story).where(Story.content_hash == content_hash)
    ).first()
