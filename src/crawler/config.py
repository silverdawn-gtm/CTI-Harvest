from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    test_database_url: str | None = None
    raw_archive_dir: Path = Path("data/raw")
    sources_config: Path = Path("config/sources.yaml")
    ontology_path: Path = Path("config/ontology.json")
    user_agent: str = (
        "cyber-threat-crawler/0.1 (research crawler; +https://github.com/local/crawler)"
    )
    request_timeout: float = 30.0

    # LLM extraction (`crawler extract`). Keys belong in .env; see .env.example.
    llm_provider: Literal["mistral", "gemini", "grok"] = "mistral"
    llm_parallel: int = 4  # requests in flight at once
    llm_requests_per_minute: int = 30
    llm_timeout: float = 120.0
    mistral_api_key: str | None = None
    mistral_model: str = "ministral-14b-latest"
    mistral_fallback_models: str = "ministral-8b-latest"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.8-flash"
    gemini_fallback_models: str = ""
    grok_api_key: str | None = None
    grok_model: str = "grok-4-fast-non-reasoning"
    grok_fallback_models: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
