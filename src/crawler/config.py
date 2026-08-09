from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    test_database_url: str | None = None
    raw_archive_dir: Path = Path("data/raw")
    user_agent: str = (
        "cyber-threat-crawler/0.1 (research crawler; +https://github.com/local/crawler)"
    )
    request_timeout: float = 30.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
