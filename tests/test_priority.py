from pathlib import Path

from threatlens.config import Settings, load_provider_config
from threatlens.providers.chain import FallbackLLMProvider
from threatlens.providers.priority import (
    default_provider_config,
    prioritize_provider_entries,
)


def test_default_config_is_groq_first():
    cfg = default_provider_config()
    assert cfg["default_provider"] == "groq"
    assert cfg["providers"][0]["name"] == "groq"
    assert cfg["providers"][1]["name"] == "openrouter"


def test_prioritize_puts_groq_before_openrouter_even_if_reversed():
    entries = [
        {"name": "openrouter", "models": ["a:free"]},
        {"name": "groq", "models": ["llama-3.3-70b-versatile"]},
    ]
    ordered = prioritize_provider_entries(entries, default_provider="groq")
    assert [e["name"] for e in ordered] == ["groq", "openrouter"]


def test_prioritize_honors_preferred_model_provider():
    entries = [
        {"name": "groq", "models": ["llama-3.3-70b-versatile"]},
        {"name": "openrouter", "models": ["openai/gpt-oss-20b:free"]},
    ]
    ordered = prioritize_provider_entries(
        entries,
        default_provider="groq",
        preferred_model="openai/gpt-oss-20b:free",
    )
    assert [e["name"] for e in ordered] == ["openrouter", "groq"]


def test_from_config_builds_groq_first_chain(tmp_path: Path):
    cfg = tmp_path / "providers.yaml"
    cfg.write_text(
        """
providers:
  - name: openrouter
    models:
      - openai/gpt-oss-20b:free
  - name: groq
    models:
      - llama-3.3-70b-versatile
default_provider: groq
""",
        encoding="utf-8",
    )
    settings = Settings.model_validate(
        {
            "GITHUB_TOKEN": "x",
            "OPENROUTER_API_KEY": "or-key",
            "GROQ_API_KEY": "groq-key",
        }
    )
    chain = FallbackLLMProvider.from_config(settings, config_path=cfg)
    names = [p.name for p in chain.providers]
    assert names[0] == "groq:llama-3.3-70b-versatile"
    assert names[1] == "openrouter:openai/gpt-oss-20b:free"


def test_load_provider_config_reads_repo_yaml():
    cfg = load_provider_config(Path("providers.yaml"))
    assert cfg.get("default_provider") == "groq"
    assert cfg["providers"][0]["name"] == "groq"
