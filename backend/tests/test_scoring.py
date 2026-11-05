from datetime import datetime, timezone, timedelta


def _cfg():
    from cvenom.config import Settings
    return Settings(database_url="postgresql://x", redis_url="redis://y")


NOW = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)


def test_kev_item_is_exploited_and_outranks_quiet_foil():
    from cvenom.scoring import CveView, Lane, lanes_for_cve, heat_rank
    cfg = _cfg()
    php = CveView("CVE-2026-109618", NOW - timedelta(hours=5), 9.2, 0.99, True)
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
