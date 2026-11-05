import re
from datetime import datetime, timezone

from cvenom.models import Story
from cvenom.textutil import content_hash, find_existing_story, sanitize_text

TAG_START = re.compile(r"<[A-Za-z/!?]")


def _assert_no_markup(out: str) -> None:
    assert TAG_START.search(out) is None, out


def test_sanitize_strips_script_and_html():
    assert sanitize_text("<b>PHP</b><script>alert(1)</script> RCE") == "PHP RCE"
    assert sanitize_text(None) == ""


def test_sanitize_plain_angle_brackets_are_escaped_not_tags():
    out = sanitize_text("5 < 6 & 7 > 2")
    assert "5" in out and "6" in out and "7" in out and "2" in out
    _assert_no_markup(out)


def test_sanitize_entity_encoded_script_is_neutralized():
    out = sanitize_text("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "<script" not in out
    assert "alert(1)" not in out
    _assert_no_markup(out)


def test_sanitize_double_encoded_script_is_neutralized():
    out = sanitize_text("&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;")
    assert "<script" not in out
    assert "alert(1)" not in out
    _assert_no_markup(out)


def test_sanitize_unterminated_img_is_neutralized():
    out = sanitize_text("<img src=x onerror=alert(1)")
    _assert_no_markup(out)


def test_sanitize_entity_encoded_unterminated_img_is_neutralized():
    out = sanitize_text("&lt;img src=x onerror=alert(1)")
    _assert_no_markup(out)


def test_sanitize_mixed_case_script_is_removed():
    out = sanitize_text("<ScRiPt>alert(1)</ScRiPt>")
    assert "alert(1)" not in out
    _assert_no_markup(out)


def test_sanitize_nested_script_is_neutralized():
    out = sanitize_text("<scr<script>ipt>alert(1)</script>")
    assert "alert(1)" not in out
    _assert_no_markup(out)


def test_sanitize_bare_unclosed_script_keeps_preceding_text():
    out = sanitize_text("x <script")
    # The unclosed token is escaped by bleach, not deleted with everything after it.
    assert out == "x &lt;script"
    _assert_no_markup(out)


def test_sanitize_unclosed_script_tag_does_not_truncate_rest_of_text():
    text = "A stored XSS in Foo 1.2 allows a <script> element in the name field; fixed in 1.3."
    out = sanitize_text(text)
    assert out.startswith("A stored XSS in Foo 1.2 allows a")
    assert "element in the name field; fixed in 1.3." in out
    _assert_no_markup(out)


def test_sanitize_unclosed_style_tag_does_not_truncate_rest_of_text():
    out = sanitize_text("Bypass via <style> injection, then CSRF.")
    assert out.startswith("Bypass via")
    assert "injection, then CSRF." in out
    _assert_no_markup(out)


def test_content_hash_is_stable_and_order_sensitive():
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
