from datetime import datetime, timezone

from cvenom.models import Story
from cvenom.textutil import content_hash, find_existing_story, sanitize_text


def test_sanitize_strips_script_and_html():
    from cvenom.textutil import sanitize_text
    assert sanitize_text("<b>PHP</b><script>alert(1)</script> RCE") == "PHP RCE"
    assert sanitize_text(None) == ""

def test_sanitize_keeps_plain_angle_brackets_and_ampersand_literal():
    from cvenom.textutil import sanitize_text
    out = sanitize_text("5 < 6 & 7 > 2")
    assert out == "5 < 6 & 7 > 2"
    assert "&lt;" not in out and "&amp;" not in out and "&gt;" not in out


def test_sanitize_entity_encoded_markup_is_neutralized():
    from cvenom.textutil import sanitize_text
    out = sanitize_text("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "<script" not in out
    assert "alert(1)" not in out


def test_sanitize_double_encoded_markup_is_neutralized():
    from cvenom.textutil import sanitize_text
    out = sanitize_text("&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;")
    assert "<script" not in out
    assert "alert(1)" not in out


def test_content_hash_is_stable_and_order_sensitive():
    from cvenom.textutil import content_hash
    assert content_hash("t","s") == content_hash("t","s")
    assert content_hash("t","s") != content_hash("s","t")


def _story(url: str, digest: str) -> Story:
    return Story(
        url=url,
        content_hash=digest,
        source="test",
        title="t",
        summary="s",
        published=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_find_existing_story_by_url_then_hash(db_session):
    story = _story("https://example.com/a", content_hash("t", "s"))
    db_session.add(story)
    db_session.flush()

    assert find_existing_story(db_session, "https://example.com/a", "other") is story
    assert find_existing_story(db_session, "https://example.com/zz", content_hash("t", "s")) is story
    assert find_existing_story(db_session, "https://example.com/zz", "nope") is None
