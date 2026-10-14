from pathlib import Path

from deslop.config.settings import Settings, get_settings, reset_settings_cache


def test_defaults_are_local_first():
    s = Settings(_env_file=None)
    assert s.llm_provider == "none"
    assert s.embedding_provider == "local"
    assert s.embedding_model == "BAAI/bge-m3"
    assert s.allow_production is False
    assert s.is_sqlite is True


def test_env_override(monkeypatch):
    monkeypatch.setenv("DESLOP_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("DESLOP_DATABASE_URL", "postgresql+psycopg://u:p@h:5432/db")
    reset_settings_cache()
    s = get_settings()
    assert s.llm_provider == "ollama"
    assert s.is_sqlite is False
    reset_settings_cache()


def test_prod_flag(monkeypatch):
    monkeypatch.setenv("DESLOP_ENV", "production")
    reset_settings_cache()
    assert get_settings().is_prod is True
    reset_settings_cache()


def test_env_example_is_loadable():
    example = Path(__file__).resolve().parents[1] / ".env.example"
    assert example.is_file()
    keys = set()
    for line in example.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0])
    assert "DESLOP_DATABASE_URL" in keys
    assert "DESLOP_LLM_PROVIDER" in keys
    # no secrets committed
    assert "DESLOP_SECRET_KEY" in keys
