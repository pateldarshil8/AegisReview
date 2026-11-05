"""Settings loaded from environment variables and an optional .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


@dataclass
class Settings:
    api_key: str
    model: str
    fallback_models: list
    max_retries: int
    delay: float
    min_interval: float
    timeout: int
    concurrency: int
    temperature: float | None
    max_output_tokens: int
    cache_dir: str | None


def _num(name: str, default, cast):
    try:
        return cast(os.environ.get(name, default))
    except ValueError:
        return default


def _split(name: str) -> list:
    return [m.strip() for m in os.environ.get(name, "").split(",") if m.strip()]


def load_settings(env_file: str | None = None, model: str | None = None) -> Settings:
    if env_file:
        load_env_file(Path(env_file))
    load_env_file(Path.cwd() / ".env")
    load_env_file(REPO_ROOT / ".env")
    temp = os.environ.get("AI_TEMPERATURE")
    return Settings(
        api_key=os.environ.get("ANTHROPIC_API_KEY", "").strip(),
        model=(model or os.environ.get("ANTHROPIC_MODEL") or "claude-sonnet-5-5").strip(),
        fallback_models=_split("ANTHROPIC_FALLBACK_MODELS"),
        max_retries=_num("AI_MAX_RETRIES", 5, int),
        delay=_num("AI_REQUEST_DELAY_SECONDS", 2.0, float),
        min_interval=_num("AI_MIN_INTERVAL_SECONDS", 1.0, float),
        timeout=_num("AI_TIMEOUT_SECONDS", 120, int),
        concurrency=max(1, _num("AI_CONCURRENCY", 3, int)),
        temperature=float(temp) if temp else None,
        max_output_tokens=_num("AI_MAX_OUTPUT_TOKENS", 32768, int),
        cache_dir=None if os.environ.get("AI_CACHE", "1") == "0" else os.environ.get("AI_CACHE_DIR", str(REPO_ROOT / ".aegis-cache")),
    )
