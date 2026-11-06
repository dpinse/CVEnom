from datetime import UTC, datetime, timedelta, timezone


def _cfg():
    from cvenom.config import Settings
    return Settings(database_url="postgresql://x", redis_url="redis://y")


NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)


def test_kev_item_is_exploited_and_outranks_quiet_foil():
    from cvenom.scoring import CveView, Lane, heat_rank, lanes_for_cve
    cfg = _cfg()
    php = CveView("CVE-2026-109618", NOW - timedelta(hours=5), 9.2, 0.99, True, kev_added=NOW.date())
    foil = CveView("CVE-2026-115560", NOW - timedelta(hours=5), 9.0, 0.30, False)
    assert Lane.EXPLOITED in lanes_for_cve(php, NOW, cfg)
    assert Lane.EXPLOITED not in lanes_for_cve(foil, NOW, cfg)
    assert heat_rank(php, NOW, cfg) > heat_rank(foil, NOW, cfg)


def test_quiet_foil_is_fresh_only_not_likely():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    foil = CveView("CVE-2026-115560", NOW - timedelta(hours=5), 9.0, 0.30, False)
    assert lanes_for_cve(foil, NOW, cfg) == {Lane.FRESH}


def test_fresh_window_uses_utc_and_expires():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    old = CveView("CVE-2026-9", NOW - timedelta(hours=72), 9.5, 0.10, False)
    assert Lane.FRESH not in lanes_for_cve(old, NOW, cfg)


def test_likely_uses_percentile_threshold():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    hot = CveView("CVE-2026-2", NOW - timedelta(days=10), 7.0, 0.96, False)
    assert Lane.LIKELY in lanes_for_cve(hot, NOW, cfg)


def test_kev_tier_decides_even_with_low_signals():
    from cvenom.scoring import CveView, heat_rank
    cfg = _cfg()
    kev = CveView("CVE-1", NOW - timedelta(days=30), 5.0, 0.1, True)
    hot = CveView("CVE-2", NOW - timedelta(hours=1), 10.0, 0.99, False, recent_story_count=10)
    assert heat_rank(kev, NOW, cfg) > heat_rank(hot, NOW, cfg)


def test_likely_boundary():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    old = NOW - timedelta(days=10)
    assert Lane.LIKELY in lanes_for_cve(CveView("a", old, 1.0, 0.95, False), NOW, cfg)
    assert Lane.LIKELY not in lanes_for_cve(CveView("b", old, 1.0, 0.949, False), NOW, cfg)


def test_fresh_boundaries():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    assert Lane.FRESH in lanes_for_cve(CveView("a", NOW - timedelta(hours=48), 9.0, 0.1, False), NOW, cfg)
    assert Lane.FRESH not in lanes_for_cve(CveView("b", NOW - timedelta(hours=49), 9.0, 0.1, False), NOW, cfg)
    assert Lane.FRESH not in lanes_for_cve(CveView("c", NOW - timedelta(hours=1), 8.9, 0.1, False), NOW, cfg)
    assert Lane.FRESH not in lanes_for_cve(CveView("d", None, 9.5, 0.1, False), NOW, cfg)


def test_loud_boundary():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    old = NOW - timedelta(days=10)
    assert Lane.LOUD not in lanes_for_cve(CveView("a", old, 1.0, 0.1, False, 0), NOW, cfg)
    assert Lane.LOUD in lanes_for_cve(CveView("b", old, 1.0, 0.1, False, 1), NOW, cfg)


def test_utc_normalization_tz_aware_and_naive():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    # 12:00Z minus 47h expressed at +05:00 -> still fresh; 49h -> not.
    tz = timezone(timedelta(hours=5))
    fresh = (NOW - timedelta(hours=47)).astimezone(tz)
    stale = (NOW - timedelta(hours=49)).astimezone(tz)
    assert Lane.FRESH in lanes_for_cve(CveView("a", fresh, 9.5, 0.1, False), NOW, cfg)
    assert Lane.FRESH not in lanes_for_cve(CveView("b", stale, 9.5, 0.1, False), NOW, cfg)
    naive = (NOW - timedelta(hours=47)).replace(tzinfo=None)
    assert Lane.FRESH in lanes_for_cve(CveView("c", naive, 9.5, 0.1, False), NOW, cfg)


def test_exploited_window_boundary():
    from datetime import date

    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    now = datetime(2026, 11, 5, 23, 30, tzinfo=UTC)
    edge = CveView("a", None, None, None, True, kev_added=date(2026, 10, 6))
    past = CveView("b", None, None, None, True, kev_added=date(2026, 10, 5))
    assert Lane.EXPLOITED in lanes_for_cve(edge, now, cfg)
    assert Lane.EXPLOITED not in lanes_for_cve(past, now, cfg)


def test_kev_without_date_not_exploited():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    v = CveView("a", NOW, None, None, True, kev_added=None)
    assert Lane.EXPLOITED not in lanes_for_cve(v, NOW, cfg)


def test_likely_requires_publish_within_window():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    new = CveView("a", NOW - timedelta(days=29), 5.0, 0.99, False)
    old = CveView("b", NOW - timedelta(days=31), 5.0, 0.99, False)
    none = CveView("c", None, 5.0, 0.99, False)
    assert Lane.LIKELY in lanes_for_cve(new, NOW, cfg)
    assert Lane.LIKELY not in lanes_for_cve(old, NOW, cfg)
    assert Lane.LIKELY not in lanes_for_cve(none, NOW, cfg)


def test_exploited_window_uses_utc_date_for_non_utc_now():
    from datetime import date

    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg = _cfg()
    now = datetime(2026, 11, 5, 23, 30, tzinfo=timezone(timedelta(hours=-5)))  # 2026-11-06T04:30Z
    edge = CveView("a", None, None, None, True, kev_added=date(2026, 10, 7))
    past = CveView("b", None, None, None, True, kev_added=date(2026, 10, 6))
    assert Lane.EXPLOITED in lanes_for_cve(edge, now, cfg)
    assert Lane.EXPLOITED not in lanes_for_cve(past, now, cfg)
