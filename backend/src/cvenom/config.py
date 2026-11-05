from functools import lru_cache

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
