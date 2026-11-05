"""AI provider clients (Gemini and Claude) behind one interface.

Shared behaviour: JSON output parsing, request throttling, retries with backoff,
model fallback, response caching, and API key masking.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from .config import Settings

RETRYABLE_CODES = {429, 500, 502, 503, 504, 529}


class AIError(Exception):
    pass


def parse_json_text(text: str):
    t = text.strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    a, b = t.find("{"), t.rfind("}")
    if a != -1 and b > a:
        try:
            return json.loads(t[a:b + 1])
        except json.JSONDecodeError:
            pass
    raise ValueError("model did not return valid JSON")


def _require_key(settings: Settings, env_name: str) -> None:
    key = settings.api_key
    if not key or key.upper().startswith("PASTE_") or key.lower().startswith("your_"):
        raise AIError(f"{env_name} is not set. Copy .env.example to .env and add your key.")


class BaseClient:
    provider = ""
    label = ""

    def __init__(self, settings: Settings):
        self.s = settings
        self._lock = threading.Lock()
        self._next_ok = 0.0
        self.used: Counter = Counter()
        self.cache_hits = 0

    # ---- provider hooks
    def _call(self, model: str, system: str, prompt: str) -> str:  # pragma: no cover
        raise NotImplementedError

    # ---- shared helpers
    def _mask(self, text: str) -> str:
        return text.replace(self.s.api_key, "***") if self.s.api_key else text

    def _classify(self, e: Exception, multi_model: bool) -> tuple[bool, bool]:
        """Return (retry, rate_limited) for a provider exception."""
        msg = str(e)
        code = getattr(e, "code", None)
        if not isinstance(code, int):
            code = getattr(e, "status_code", None)
        name = type(e).__name__
        rate_limited = code == 429 or "RESOURCE_EXHAUSTED" in msg or name == "RateLimitError"
        retry = (
            rate_limited
            or code in RETRYABLE_CODES
            or (code == 404 and multi_model)  # model retired/unavailable: try the next one
            or "UNAVAILABLE" in msg
            or "timed out" in msg.lower()
            or "Timeout" in name
            or name == "APIConnectionError"
        )
        return retry, rate_limited

    def _throttle(self) -> None:
        """Space requests out so per-minute quotas are respected."""
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_ok - now)
            self._next_ok = max(now, self._next_ok) + self.s.min_interval
        if wait:
            time.sleep(wait)

    def _cache_path(self, system: str, prompt: str):
        if not self.s.cache_dir:
            return None
        prefix = "" if self.provider == "gemini" else self.provider + "\0"  # keeps older Gemini cache entries valid
        key = hashlib.sha256((prefix + system + "\0" + prompt).encode("utf-8")).hexdigest()
        return Path(self.s.cache_dir) / f"{key}.json"

    def generate_json(self, system: str, prompt: str, label: str = "call"):
        cache = self._cache_path(system, prompt)
        if cache is not None and cache.is_file():
            try:
                data = json.loads(cache.read_text(encoding="utf-8"))
                model = None
                if isinstance(data, dict) and data.get("_aegis_cache") == 1:
                    model, data = data.get("model"), data.get("result")
                self.used[model or self.s.model] += 1  # entries from older versions do not record the model
                self.cache_hits += 1
                print(f"  [{label}] using cached AI response", file=sys.stderr)
                return data
            except (OSError, json.JSONDecodeError):
                pass
        result, model = self._generate_json_uncached(system, prompt, label)
        empty = isinstance(result, dict) and result.get("findings") == []
        if cache is not None and not empty:  # never cache "found nothing": it may be a weak or failed answer
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps({"_aegis_cache": 1, "model": model, "result": result}), encoding="utf-8")
            except OSError:
                pass
        return result

    def _generate_json_uncached(self, system: str, prompt: str, label: str):
        last: Exception | None = None
        models = [self.s.model] + [m for m in self.s.fallback_models if m != self.s.model]
        for attempt in range(self.s.max_retries + 1):
            retry = True
            rate_limited = False
            model = models[attempt % len(models)]
            try:
                self._throttle()
                result = parse_json_text(self._call(model, system, prompt))
                self.used[model] += 1
                return result, model
            except ValueError as e:
                last = e
            except Exception as e:  # noqa: BLE001
                last = e
                retry, rate_limited = self._classify(e, len(models) > 1)
            if not retry or attempt >= self.s.max_retries:
                break
            cycle, pos = divmod(attempt, len(models))
            if len(models) > 1 and pos < len(models) - 1:
                wait = 3 + random.random()
            else:
                wait = (65 if rate_limited else min(45, 6 * 2 ** cycle)) + random.random()
            print(f"  [{label}] retry {attempt + 1}/{self.s.max_retries} in {wait:.0f}s, "
                  f"next model: {models[(attempt + 1) % len(models)]} "
                  f"({type(last).__name__}: {self._mask(str(last))[:160]})", file=sys.stderr)
            time.sleep(wait)
        raise AIError(self._mask(f"{label}: {type(last).__name__}: {last}")[:500])


class GeminiClient(BaseClient):
    provider = "gemini"
    label = "Google Gemini"

    def __init__(self, settings: Settings):
        super().__init__(settings)
        _require_key(settings, "GEMINI_API_KEY")
        try:
            from google import genai
            from google.genai import types
        except ImportError as e:  # pragma: no cover
            raise AIError("The 'google-genai' package is missing. Run: pip install -r requirements.txt") from e
        self._types = types
        self.client = genai.Client(api_key=settings.api_key, http_options=types.HttpOptions(timeout=settings.timeout * 1000))

    def _call(self, model: str, system: str, prompt: str) -> str:
        cfg = {"system_instruction": system, "response_mime_type": "application/json",
               "max_output_tokens": self.s.max_output_tokens}
        if self.s.temperature is not None:
            cfg["temperature"] = self.s.temperature
        resp = self.client.models.generate_content(model=model, contents=prompt,
                                                   config=self._types.GenerateContentConfig(**cfg))
        if not resp.text:
            raise ValueError("empty response (possibly blocked by safety filters)")
        return resp.text


class AnthropicClient(BaseClient):
    provider = "anthropic"
    label = "Anthropic Claude"

    def __init__(self, settings: Settings):
        super().__init__(settings)
        _require_key(settings, "ANTHROPIC_API_KEY")
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise AIError("The 'anthropic' package is missing. Run: pip install -r requirements.txt") from e
        self.client = anthropic.Anthropic(api_key=settings.api_key, timeout=float(settings.timeout), max_retries=0)

    def _call(self, model: str, system: str, prompt: str) -> str:
        kwargs = {"model": model, "max_tokens": min(self.s.max_output_tokens, 16000), "system": system,
                  "messages": [{"role": "user", "content": prompt}]}
        if self.s.temperature is not None:
            kwargs["temperature"] = self.s.temperature
        resp = self.client.messages.create(**kwargs)
        text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text")
        if not text:
            raise ValueError("empty response")
        return text


def make_client(settings: Settings) -> BaseClient:
    if settings.provider == "anthropic":
        return AnthropicClient(settings)
    return GeminiClient(settings)
