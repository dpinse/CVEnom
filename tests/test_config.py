def test_settings_defaults_and_env_override(monkeypatch):
    from cvenom.config import Settings
    s = Settings(database_url="postgresql://x", redis_url="redis://y")
    assert s.epss_percentile_threshold == 0.95
    assert s.fresh_cvss_floor == 9.0
    assert s.fresh_window_hours == 48
    assert s.nvd_api_key is None
    monkeypatch.setenv("FRESH_WINDOW_HOURS", "24")
    assert Settings(database_url="postgresql://x", redis_url="redis://y").fresh_window_hours == 24
