import ipaddress
from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    redis_url: str
    nvd_api_key: SecretStr | None = None
    vulncheck_api_token: SecretStr | None = None
    github_token: SecretStr | None = None
    epss_percentile_threshold: float = 0.95
    fresh_cvss_floor: float = 9.0
    fresh_window_hours: int = 48
    loud_window_hours: int = 72
    velocity_window_days: int = 30
    backfill_days: int = 90
    # KEV/VulnCheck: alert only for entries whose own add date is this recent.
    kev_alert_max_age_days: int = 14
    geo_retention_days: int = 30
    geoip_dir: str = "data/geoip"
    maxmind_account_id: str | None = None
    maxmind_license_key: SecretStr | None = None
    ransomware_live_api_key: SecretStr | None = None
    cf_radar_token: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None

    # --- API / auth / alerts (Plan 3) ---
    # base64 of 32 random bytes; required only when the secret box is used.
    secrets_key: SecretStr | None = None
    public_read: bool = True
    api_docs: bool = False
    cors_origins: list[str] = []
    trusted_proxy_cidrs: list[str] = []
    jwt_issuer: str = "cvenom"
    jwt_audience: str = "cvenom-api"
    access_ttl_minutes: int = 15
    refresh_ttl_days: int = 30
    jwt_rotation_days: int = 7
    max_body_bytes: int = 65536
    rate_anon_per_min: int = 60
    rate_login_per_15min_ip: int = 10
    rate_login_per_15min_email: int = 10
    rate_authed_per_min: int = 300
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from_addr: str | None = None
    smtp_starttls: bool = True

    @field_validator(
        "nvd_api_key", "vulncheck_api_token", "github_token", "maxmind_license_key",
        "ransomware_live_api_key", "cf_radar_token", "abusech_auth_key",
        "secrets_key", "smtp_password",
        mode="before",
    )
    @classmethod
    def _empty_secret_is_none(cls, v):
        # An empty env value (KEY=) means "not configured".
        if isinstance(v, str) and v == "":
            return None
        if isinstance(v, SecretStr) and v.get_secret_value() == "":
            return None
        return v

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        for entry in v:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                raise ValueError(f"invalid trusted_proxy_cidrs entry: {entry!r}") from None
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
