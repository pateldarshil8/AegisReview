"""Data models shared across the pipeline."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES = ["high", "medium", "low"]
STATUSES = ["confirmed", "needs_validation"]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _choice(value: Any, allowed: list[str], default: str) -> str:
    v = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    return v if v in allowed else default


@dataclass
class Finding:
    id: str = ""
    title: str = ""
    category: str = ""
    cwe: str = ""
    owasp: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    status: str = "needs_validation"
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    evidence: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    secure_code: str = ""
    validation_notes: str = ""
    related: list = field(default_factory=list)  # [{file,line_start,line_end,note}]
    source: str = "ai"  # "ai" or "heuristic"
    lens: str = ""
    cid: str = ""  # candidate id used during consolidation

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("cid", None)
        return d

    @classmethod
    def from_raw(cls, raw: dict, lens: str = "") -> "Finding":
        related = []
        for r in raw.get("related_locations") or raw.get("related") or []:
            if isinstance(r, dict) and r.get("file"):
                related.append({
                    "file": str(r.get("file")),
                    "line_start": _int(r.get("line_start")),
                    "line_end": _int(r.get("line_end") or r.get("line_start")),
                    "note": str(r.get("note") or ""),
                })
        ls = _int(raw.get("line_start"))
        return cls(
            title=str(raw.get("title") or "").strip(),
            category=str(raw.get("category") or "").strip(),
            cwe=str(raw.get("cwe") or "").strip(),
            owasp=str(raw.get("owasp") or "").strip(),
            severity=_choice(raw.get("severity"), SEVERITIES, "medium"),
            confidence=_choice(raw.get("confidence"), CONFIDENCES, "medium"),
            status=_choice(raw.get("status"), STATUSES, "needs_validation"),
            file=str(raw.get("file") or "").strip(),
            line_start=ls,
            line_end=_int(raw.get("line_end"), ls) or ls,
            evidence=str(raw.get("evidence") or ""),
            description=str(raw.get("description") or "").strip(),
            impact=str(raw.get("impact") or "").strip(),
            remediation=str(raw.get("remediation") or "").strip(),
            secure_code=str(raw.get("secure_code") or "").rstrip(),
            validation_notes=str(raw.get("validation_notes") or "").strip(),
            related=related,
            lens=lens,
        )


@dataclass
class Assessment:
    app_name: str
    date: str
    tool_version: str
    model: str
    ai_used: bool
    findings: list = field(default_factory=list)
    rejected: list = field(default_factory=list)  # [{title,file,line,reason}]
    executive_summary: str = ""
    overall_assessment: str = ""
    priorities: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    file_lines: dict = field(default_factory=dict)  # path -> list[str] (redacted), for report snippets
    languages: dict = field(default_factory=dict)   # path -> language
