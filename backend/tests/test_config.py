def test_settings_defaults_and_env_override(monkeypatch):
    from cvenom.config import Settings
    s = Settings(database_url="postgresql://x", redis_url="redis://y")
    assert s.epss_percentile_threshold == 0.95
    assert s.fresh_cvss_floor == 9.0
    assert s.fresh_window_hours == 48
    assert s.nvd_api_key is None
    assert s.kev_alert_max_age_days == 14
    monkeypatch.setenv("FRESH_WINDOW_HOURS", "24")
    assert Settings(database_url="postgresql://x", redis_url="redis://y").fresh_window_hours == 24


SECRET_ENVS = {
    "NVD_API_KEY": "SEKRIT-nvd-123",
    "VULNCHECK_API_TOKEN": "SEKRIT-vc-123",
    "GITHUB_TOKEN": "SEKRIT-gh-123",
    "MAXMIND_LICENSE_KEY": "SEKRIT-mm-123",
    "RANSOMWARE_LIVE_API_KEY": "SEKRIT-rw-123",
    "CF_RADAR_TOKEN": "SEKRIT-cf-123",
    "ABUSECH_AUTH_KEY": "SEKRIT-ab-123",
    "SECRETS_KEY": "SEKRIT-sk-123",
    "SMTP_PASSWORD": "SEKRIT-smtp-123",
}


def test_repr_and_dump_hide_every_secret(monkeypatch):
    from cvenom.config import get_settings

    for k, v in SECRET_ENVS.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    try:
        s = get_settings()
        text = repr(s) + str(s) + str(s.model_dump())
        for v in SECRET_ENVS.values():
            assert v not in text
        assert s.nvd_api_key.get_secret_value() == "SEKRIT-nvd-123"
        assert s.smtp_password.get_secret_value() == "SEKRIT-smtp-123"
    finally:
        get_settings.cache_clear()


def test_empty_secret_env_means_disabled(monkeypatch):
    from cvenom.config import Settings

    for k in SECRET_ENVS:
        monkeypatch.setenv(k, "")
    s = Settings(database_url="postgresql://x", redis_url="redis://y", _env_file=None)
    for name in (
        "nvd_api_key", "vulncheck_api_token", "github_token", "maxmind_license_key",
        "ransomware_live_api_key", "cf_radar_token", "abusech_auth_key",
        "secrets_key", "smtp_password",
    ):
        assert getattr(s, name) is None, name


def test_new_setting_defaults():
    from cvenom.config import Settings

    s = Settings(database_url="postgresql://x", redis_url="redis://y", _env_file=None)
    assert s.public_read is True
    assert s.cors_origins == [] and s.trusted_proxy_cidrs == []
    assert (s.jwt_issuer, s.jwt_audience) == ("cvenom", "cvenom-api")
    assert (s.access_ttl_minutes, s.refresh_ttl_days, s.jwt_rotation_days) == (15, 30, 7)
    assert s.smtp_host is None and s.smtp_port == 587 and s.smtp_starttls is True
    assert s.smtp_username is None and s.smtp_password is None and s.smtp_from_addr is None
    assert s.max_body_bytes == 65536
    assert (s.rate_anon_per_min, s.rate_login_per_15min_ip) == (60, 10)
    assert (s.rate_login_per_15min_email, s.rate_authed_per_min) == (10, 300)


def test_list_settings_parse_json_env(monkeypatch):
    from cvenom.config import Settings

    monkeypatch.setenv("CORS_ORIGINS", '["https://x.example"]')
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", '["10.0.0.0/8", "::1/128"]')
    s = Settings(database_url="postgresql://x", redis_url="redis://y", _env_file=None)
    assert s.cors_origins == ["https://x.example"]
    assert s.trusted_proxy_cidrs == ["10.0.0.0/8", "::1/128"]


def test_bad_trusted_proxy_cidr_fails_at_load():
    import pytest
    from pydantic import ValidationError

    from cvenom.config import Settings

    with pytest.raises(ValidationError):
        Settings(
            database_url="postgresql://x", redis_url="redis://y",
            trusted_proxy_cidrs=["10.0.0.0/8", "not-a-cidr"], _env_file=None,
        )
