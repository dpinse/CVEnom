from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    redis_url: str
    nvd_api_key: str | None = None
    vulncheck_api_token: str | None = None
    github_token: str | None = None
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
