import re

from sqlalchemy.orm import Session

from cvenom.db import upsert_cve
from cvenom.models import Story, StoryCveLink
from cvenom.schemas import NormalizedCve

# ASCII digits only, matching NormalizedCve.cve_id validation (else ingest would raise).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE | re.ASCII)


def extract_cve_ids(text: str | None) -> set[str]:
    """Return the deduped, upper-cased CVE ids mentioned in text."""
    if not text:
        return set()
    return {m.upper() for m in _CVE_RE.findall(text)}


def link_story(session: Session, story: Story, cve_ids: set[str]) -> None:
    """Link a story to CVEs, stubbing any Cve row not yet known. Idempotent."""
    for cve_id in sorted(cve_ids):
        upsert_cve(session, NormalizedCve(cve_id=cve_id))
        if session.get(StoryCveLink, (story.id, cve_id)) is None:
            session.add(StoryCveLink(story_id=story.id, cve_id=cve_id))
    session.flush()
