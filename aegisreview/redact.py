"""Redact credential-like values before source code leaves the machine."""
from __future__ import annotations

import re
from dataclasses import dataclass

PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), 0),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 0),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), 0),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b"), 0),
    (
        "credential",
        re.compile(
            r"""(?i)(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|service[_-]?role[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{8,})["']"""
        ),
        1,
    ),
]
PLACEHOLDER = re.compile(r"(?i)(example|fake|demo|dummy|sample|changeme|your[_-]|x{4,}|placeholder|test|todo|redacted|lorem)")


@dataclass
class RedactionItem:
    line: int
    kind: str
    length: int
    placeholder_like: bool


def redact_text(text: str) -> tuple[str, list[RedactionItem]]:
    spans = []  # (start, end, kind, value)
    for kind, rx, group in PATTERNS:
        for m in rx.finditer(text):
            value = m.group(group)
            if value.startswith("<REDACTED"):
                continue
            spans.append((m.start(group), m.end(group), kind, value))
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    chosen, last_end = [], -1
    for s in spans:
        if s[0] >= last_end:
            chosen.append(s)
            last_end = s[1]
    out, pos, items = [], 0, []
    for start, end, kind, value in chosen:
        ph = bool(PLACEHOLDER.search(value))
        marker = f"<REDACTED:{kind}:len={len(value)}:placeholder-like={'yes' if ph else 'no'}>"
        # keep the number of lines stable so line references stay correct
        marker += "\n" * value.count("\n")
        out.append(text[pos:start])
        out.append(marker)
        pos = end
        items.append(RedactionItem(text.count("\n", 0, start) + 1, kind, len(value), ph))
    out.append(text[pos:])
    return "".join(out), items
