from datetime import datetime, timezone

from sqlalchemy import func, select

from cvenom.db import upsert_cve
from cvenom.models import Cve, Story, StoryCveLink
from cvenom.schemas import NormalizedCve


def test_extract_cve_ids_finds_all_and_dedupes():
    from cvenom.extract import extract_cve_ids
    txt = "PHP2Shell: cve-2026-109618 and CVE-2026-109619; again CVE-2026-109618."
    assert extract_cve_ids(txt) == {"CVE-2026-109618", "CVE-2026-109619"}


def test_extract_handles_empty_and_none():
    from cvenom.extract import extract_cve_ids
    assert extract_cve_ids("") == set()
    assert extract_cve_ids(None) == set()


def _story(session, url="https://example.com/a"):
    story = Story(
        url=url, content_hash="h", source="s", title="t", summary="",
        published=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    session.add(story)
    session.flush()
    return story


def test_link_story_creates_stub_cve_and_link(db_session):
    from cvenom.extract import link_story
    story = _story(db_session)
    link_story(db_session, story, {"CVE-2026-0001"})
    cve = db_session.get(Cve, "CVE-2026-0001")
    assert cve is not None and cve.cvss is None and cve.kev is False
    assert db_session.get(StoryCveLink, (story.id, "CVE-2026-0001")) is not None


def test_link_story_is_idempotent(db_session):
    from cvenom.extract import link_story
    story = _story(db_session)
    link_story(db_session, story, {"CVE-2026-0001", "CVE-2026-0002"})
    link_story(db_session, story, {"CVE-2026-0001", "CVE-2026-0002"})
    assert db_session.scalar(select(func.count()).select_from(Cve)) == 2
    assert db_session.scalar(select(func.count()).select_from(StoryCveLink)) == 2


def test_link_story_does_not_overwrite_existing_cve(db_session):
    from cvenom.extract import link_story
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-0003", cvss=9.8, kev=True, summary="real"))
    story = _story(db_session)
    link_story(db_session, story, {"CVE-2026-0003"})
    cve = db_session.get(Cve, "CVE-2026-0003")
    assert (cve.cvss, cve.kev, cve.summary) == (9.8, True, "real")
    assert db_session.get(StoryCveLink, (story.id, "CVE-2026-0003")) is not None


def test_extract_ignores_non_ascii_digits():
    from cvenom.extract import extract_cve_ids
    # Fullwidth / Arabic-Indic digits would fail NormalizedCve validation and abort ingest.
    assert extract_cve_ids("see CVE-２０２４-１２３４ and CVE-2024-5678") == {
        "CVE-2024-5678"
    }
