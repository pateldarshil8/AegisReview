"""Generic, language-agnostic pattern hints.

Hints are NOT reported as findings when AI is available. They are leads handed to the
AI reviewers, who must confirm them against surrounding code. With --no-ai (or when the
API is unreachable) they are reported as 'needs validation' findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

JS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"}
PY = {".py"}
ANY = None


@dataclass
class Hint:
    file: str
    line: int
    rule: str
    title: str
    category: str
    cwe: str
    severity: str
    note: str
    snippet: str


RULES = [
    ("eval-use", r"\beval\s*\(|\bnew Function\s*\(", JS | PY, "Dynamic code evaluation", "Code Injection", "CWE-95", "high", "eval/new Function executes strings as code."),
    ("raw-html", r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|v-html", JS, "Unsanitized HTML rendering", "Cross-Site Scripting", "CWE-79", "medium", "Raw HTML sinks are dangerous when fed untrusted data."),
    ("sql-concat", r"""(?i)(?:query|execute|exec|raw|sql)\s*\(\s*(?:f?["'`][^"'`]*(?:select|insert|update|delete)\b[^"'`]*["'`]\s*(?:\+|%|\.format)|`[^`]*\$\{)""", ANY, "SQL built from strings", "SQL Injection", "CWE-89", "high", "SQL assembled by concatenation or interpolation."),
    ("filter-interp", r"""\.(?:or|filter|ilike|like|match)\s*\(\s*`[^`]*\$\{""", JS, "Query filter built with interpolation", "Injection", "CWE-943", "medium", "Template-interpolated filter strings can alter query logic."),
    ("rls-open", r"""(?i)(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)""", {".sql"}, "Row Level Security policy allows everything", "Broken Access Control", "CWE-862", "high", "Policy expression is always true."),
    ("rls-disabled", r"(?i)DISABLE\s+ROW\s+LEVEL\s+SECURITY", {".sql"}, "Row Level Security disabled", "Broken Access Control", "CWE-862", "high", "RLS explicitly disabled."),
    ("security-definer", r"(?i)SECURITY\s+DEFINER", {".sql"}, "SECURITY DEFINER function", "Privilege Escalation", "CWE-250", "medium", "Runs with owner privileges; verify search_path and checks."),
    ("service-role", r"(?i)service[_-]?role", ANY, "Service-role credential usage", "Excessive Privilege", "CWE-250", "medium", "Service-role keys bypass row level security."),
    ("cors-wildcard", r"""(?i)access-control-allow-origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["']""", ANY, "Wildcard CORS", "Security Misconfiguration", "CWE-942", "medium", "Any origin may call this endpoint."),
    ("tls-off", r"(?i)verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0", ANY, "TLS verification disabled", "Insecure Transport", "CWE-295", "high", "Certificate validation turned off."),
    ("token-storage", r"""(?i)(?:localStorage|sessionStorage)\.setItem\(\s*["'][^"']*(?:token|jwt|session|secret)""", JS, "Token kept in web storage", "Sensitive Data Exposure", "CWE-922", "low", "Script-readable storage exposes tokens to XSS."),
    ("log-sensitive", r"""(?i)console\.(?:log|debug|info)\(.*(?:password|token|secret|apikey)|print\(.*(?:password|token|secret)""", ANY, "Sensitive value logged", "Information Exposure", "CWE-532", "medium", "Credentials or tokens may reach logs."),
    ("weak-hash", r"(?i)\b(?:md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\b|createHash\(\s*[\"'](?:md5|sha1)[\"']", ANY, "Weak hash algorithm", "Weak Cryptography", "CWE-328", "medium", "MD5/SHA-1 are unsuitable for security purposes."),
    ("weak-random", r"Math\.random\s*\(", JS, "Non-cryptographic randomness", "Weak Randomness", "CWE-338", "low", "Math.random must not generate secrets or tokens."),
    ("shell-exec", r"""child_process|\bos\.system\s*\(|subprocess\.[a-z_]+\([^)]*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec""", ANY, "Shell command execution", "Command Injection", "CWE-78", "high", "Check whether untrusted input reaches the command."),
    ("deserialize", r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|ObjectInputStream", ANY, "Unsafe deserialization", "Insecure Deserialization", "CWE-502", "high", "Deserializing untrusted data can execute code."),
    ("debug-on", r"""(?i)\bdebug\s*[:=]\s*(?:true|True)\b|app\.run\([^)]*debug\s*=\s*True""", ANY, "Debug mode enabled", "Security Misconfiguration", "CWE-489", "low", "Debug settings can leak internals."),
    ("client-trusted-id", r"""(?i)(?:body|payload|req\.json\(\)|request\.json)[^\n]*\b(?:user_?id|owner_?id|role|is_?admin)\b""", ANY, "Identity or role taken from client input", "Broken Access Control", "CWE-639", "medium", "Client-supplied identity/role fields must not be trusted."),
]
COMPILED = [(r[0], re.compile(r[1]), r[2], *r[3:]) for r in RULES]
CREATE_TABLE = re.compile(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?\"?([a-z_][a-z0-9_]*)\"?")
ENABLE_RLS = re.compile(r"(?i)alter\s+table\s+(?:only\s+)?(?:public\.)?\"?([a-z_][a-z0-9_]*)\"?\s+enable\s+row\s+level\s+security")


def run_hints(files: list) -> list:
    """files: list of objects with .path, .language and .text (already redacted)."""
    hints: list[Hint] = []
    rls_enabled, tables = set(), []
    for f in files:
        ext = "." + f.path.rsplit(".", 1)[-1].lower() if "." in f.path else ""
        lines = f.text.splitlines()
        for i, line in enumerate(lines, 1):
            if len(line) > 600:
                continue
            for rule, rx, exts, title, cat, cwe, sev, note in COMPILED:
                if exts is not None and ext not in exts:
                    continue
                if rx.search(line):
                    hints.append(Hint(f.path, i, rule, title, cat, cwe, sev, note, line.strip()[:200]))
        if ext == ".sql":
            for m in ENABLE_RLS.finditer(f.text):
                rls_enabled.add(m.group(1).lower())
            for m in CREATE_TABLE.finditer(f.text):
                tables.append((f.path, f.text.count("\n", 0, m.start()) + 1, m.group(1).lower(), lines[f.text.count("\n", 0, m.start())].strip()[:200]))
    for path, line, table, snippet in tables:
        if table not in rls_enabled:
            hints.append(Hint(path, line, "table-no-rls", f"Table '{table}' has no Row Level Security enabled", "Broken Access Control", "CWE-862", "medium",
                              "No ENABLE ROW LEVEL SECURITY statement found for this table in the analyzed SQL.", snippet))
    return hints
