"""Environment and provider configuration."""

from pathlib import Path

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    openrouter_api_key: str = Field(default="", alias="OPENROUTER_API_KEY")
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")


def load_provider_config(path: Path | None = None) -> dict:
    """Load providers.yaml; falls back to Groq-first smart-free defaults."""
    config_path = path or Path("providers.yaml")
    if config_path.is_file():
        with config_path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    # Lazy import avoids circular import via providers.__init__.
    from threatlens.providers.priority import default_provider_config

    return default_provider_config()
