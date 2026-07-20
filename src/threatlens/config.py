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
    """Load providers.yaml; falls back to defaults matching design.md."""
    config_path = path or Path("providers.yaml")
    if config_path.is_file():
        with config_path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    return {
        "providers": [
            {
                "name": "openrouter",
                "models": [
                    "meta-llama/llama-3.3-70b-instruct:free",
                    "qwen/qwen-2.5-72b-instruct:free",
                    "deepseek/deepseek-chat:free",
                    "google/gemini-2.0-flash-exp:free",
                ],
            },
            {
                "name": "groq",
                "models": ["llama-3.3-70b-versatile"],
            },
        ],
        "default_provider": "openrouter",
    }
