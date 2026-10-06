from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    test_database_url: str | None = None
    raw_archive_dir: Path = Path("data/raw")
    sources_config: Path = Path("config/sources.yaml")
    ontology_path: Path = Path("config/ontology.json")
    extracted_dir: Path = Path("data/extracted")
    # `crawler extract --rules-only` writes here, so rule-only output never marks a document
    # as done for an LLM run.
    extracted_rules_dir: Path = Path("data/extracted-rules")
    user_agent: str = (
        "cyber-threat-crawler/0.1 (research crawler; +https://github.com/silverdawn-gtm/CTI-Harvest)"
    )
    request_timeout: float = 30.0

    # LLM extraction (`crawler extract`). Keys belong in .env; see .env.example.
    llm_provider: Literal["mistral", "gemini", "grok"] = "mistral"
    llm_parallel: int = Field(4, ge=1)  # requests in flight at once
    llm_requests_per_minute: int = Field(30, ge=1)
    llm_timeout: float = 120.0
    mistral_api_key: str | None = None
    mistral_model: str = "ministral-14b-latest"
    mistral_fallback_models: str = "ministral-8b-latest"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.8-flash"
    gemini_fallback_models: str = "gemini-3.6-flash,gemini-2.5-flash"
    grok_api_key: str | None = None
    grok_model: str = "grok-4-fast-non-reasoning"
    grok_fallback_models: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
