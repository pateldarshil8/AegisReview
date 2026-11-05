"""Thin Gemini wrapper: JSON output, retries with backoff, key masking."""
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

RETRYABLE_CODES = {429, 500, 502, 503, 504}


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


class GeminiClient:
    def __init__(self, settings: Settings):
        if not settings.api_key:
            raise AIError("GEMINI_API_KEY is not set. Copy .env.example to .env and add your key.")
        try:
            from google import genai
            from google.genai import types
        except ImportError as e:  # pragma: no cover
            raise AIError("The 'google-genai' package is missing. Run: pip install -r requirements.txt") from e
        self._types = types
        self.s = settings
        self._lock = threading.Lock()
        self.used: Counter = Counter()
        self._next_ok = 0.0
        self.client = genai.Client(
            api_key=settings.api_key,
            http_options=types.HttpOptions(timeout=settings.timeout * 1000),
        )

    def _mask(self, text: str) -> str:
        return text.replace(self.s.api_key, "***") if self.s.api_key else text

    def _throttle(self) -> None:
        """Space requests out so free-tier per-minute quotas are respected."""
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_ok - now)
            self._next_ok = max(now, self._next_ok) + self.s.min_interval
        if wait:
            time.sleep(wait)

    def _cache_path(self, system: str, prompt: str):
        if not self.s.cache_dir:
            return None
        key = hashlib.sha256((system + "\0" + prompt).encode("utf-8")).hexdigest()
        return Path(self.s.cache_dir) / f"{key}.json"

    def generate_json(self, system: str, prompt: str, label: str = "call"):
        cache = self._cache_path(system, prompt)
        if cache is not None and cache.is_file():
            try:
                data = json.loads(cache.read_text(encoding="utf-8"))
                self.used["cached response"] += 1
                print(f"  [{label}] using cached AI response", file=sys.stderr)
                return data
            except (OSError, json.JSONDecodeError):
                pass
        result = self._generate_json_uncached(system, prompt, label)
        empty = isinstance(result, dict) and result.get("findings") == []
        if cache is not None and not empty:  # never cache "found nothing": it may be a weak or failed answer
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(result), encoding="utf-8")
            except OSError:
                pass
        return result

    def _generate_json_uncached(self, system: str, prompt: str, label: str):
        cfg = {
            "system_instruction": system,
            "response_mime_type": "application/json",
            "max_output_tokens": self.s.max_output_tokens,
        }
        if self.s.temperature is not None:
            cfg["temperature"] = self.s.temperature
        config = self._types.GenerateContentConfig(**cfg)
        last: Exception | None = None
        models = [self.s.model] + [m for m in self.s.fallback_models if m != self.s.model]
        for attempt in range(self.s.max_retries + 1):
            retry = True
            rate_limited = False
            model = models[attempt % len(models)]
            try:
                self._throttle()
                resp = self.client.models.generate_content(model=model, contents=prompt, config=config)
                text = resp.text
                if not text:
                    raise ValueError("empty response (possibly blocked by safety filters)")
                result = parse_json_text(text)
                self.used[model] += 1
                return result
            except ValueError as e:
                last = e
            except Exception as e:  # noqa: BLE001
                last = e
                msg = str(e)
                code = getattr(e, "code", None)
                rate_limited = code == 429 or "RESOURCE_EXHAUSTED" in msg
                retry = (
                    code in RETRYABLE_CODES
                    or (code == 404 and len(models) > 1)  # model retired/unavailable: try the next one
                    or "RESOURCE_EXHAUSTED" in msg
                    or "UNAVAILABLE" in msg
                    or "timed out" in msg.lower()
                    or "Timeout" in type(e).__name__
                )
            if not retry or attempt >= self.s.max_retries:
                break
            # rotate models quickly; back off harder once every model has been tried
            cycle, pos = divmod(attempt, len(models))
            if len(models) > 1 and pos < len(models) - 1:
                wait = 3 + random.random()
            else:
                wait = (65 if rate_limited else min(45, 6 * 2 ** cycle)) + random.random()
            print(f"  [{label}] retry {attempt + 1}/{self.s.max_retries} in {wait:.0f}s, next model: {models[(attempt + 1) % len(models)]} "
                  f"({type(last).__name__}: {self._mask(str(last))[:160]})", file=sys.stderr)
            time.sleep(wait)
        raise AIError(self._mask(f"{label}: {type(last).__name__}: {last}")[:500])
