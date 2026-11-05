"""Render an Assessment as Markdown, self-contained HTML, and JSON."""
from __future__ import annotations

import html
import json
import textwrap
from dataclasses import asdict

from .models import SEVERITIES, Assessment, Finding

STATUS_LABEL = {"confirmed": "Confirmed", "needs_validation": "Needs validation"}
SEV_COLOR = {"critical": "#7f1d1d", "high": "#c2410c", "medium": "#b45309", "low": "#1d4ed8", "info": "#475569"}


def severity_counts(findings: list[Finding]) -> dict:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


def risk_rating(findings: list[Finding]) -> str:
    c = severity_counts(findings)
    if c["critical"]:
        return "Critical"
    if c["high"]:
        return "High"
    if c["medium"]:
        return "Moderate"
    if c["low"] or c["info"]:
        return "Low"
    return "No findings"


def snippet(asm: Assessment, f: Finding, cap: int = 15) -> str:
    lines = asm.file_lines.get(f.file)
    if lines and f.line_start:
        a = f.line_start - 1
        b = min(max(f.line_end, f.line_start), a + cap)
        return textwrap.dedent("\n".join(lines[a:b]))
    return textwrap.dedent(f.evidence)


def loc(f: Finding) -> str:
    if not f.line_start:
        return "n/a"
    return f"line {f.line_start}" if f.line_end <= f.line_start else f"lines {f.line_start}-{f.line_end}"


def _fence(code: str, lang: str = "") -> str:
    ticks = "```"
    while ticks in code:
        ticks += "`"
    return f"{ticks}{lang}\n{code}\n{ticks}"


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _related(f: Finding) -> list[str]:
    out = []
    for r in f.related:
        where = r["file"] + (f":{r['line_start']}" if r.get("line_start") else "")
        out.append(f"`{where}`" + (f" ({r['note']})" if r.get("note") else ""))
    return out


# ----------------------------------------------------------------------- shared text
# Structure follows the organizers' templates/SAMPLE-REPORT.md: same sections, order, field names.
CONFIDENCE_TEXT = {
    "confirmed": "the weakness is directly evident in the code shown.",
    "needs_validation": "the weakness is plausible but depends on context outside the analyzed code.",
}
NO_SNIPPET = "No code-level change applies to this finding; follow the recommended fix above."
SCOPE_FIXED = [
    "Static code review only",
    "No exploit execution",
    "No runtime penetration testing",
    "No guarantee that every vulnerability is found",
    "Some findings may require manual confirmation",
]
CONCLUSION = [
    "Address high-impact issues first and validate the remediation using appropriate testing.",
    "A follow-up security review is recommended after the changes are implemented.",
]


def _count_rows(findings: list[Finding]) -> list[tuple[str, int]]:
    c = severity_counts(findings)
    rows = [("Critical", c["critical"]), ("High", c["high"]), ("Medium", c["medium"]), ("Low", c["low"])]
    if c["info"]:
        rows.append(("Informational", c["info"]))
    return rows


def _exec_summary(asm: Assessment) -> str:
    text = (asm.executive_summary or "No summary available.").strip()
    return text + " AI-assisted findings should be validated before being treated as confirmed vulnerabilities."


def _category(f: Finding) -> str:
    return f.category or "n/a"


def _cwe(f: Finding) -> str:
    base = f.cwe or "n/a"
    return f"{base} (OWASP Top 10: {f.owasp})" if f.owasp else base


def _confidence(f: Finding) -> str:
    return f"{f.confidence.capitalize()} — {CONFIDENCE_TEXT[f.status]}"


def _validation(f: Finding) -> str:
    parts = []
    if f.validation_notes:
        parts.append(f.validation_notes)
    rel = [r.replace("`", "") for r in _related(f)]
    if rel:
        parts.append("Related locations: " + "; ".join(rel) + ".")
    return " ".join(parts) or "No further validation is needed beyond reviewing the recommended fix in context."


def _short_action(f: Finding) -> str:
    return f.remediation.split(". ")[0].rstrip(".") if f.remediation else "Review"


def _scope_extras(asm: Assessment) -> list[str]:
    st = asm.stats
    out = [
        f"Analyzed {st.get('files_analyzed', 0)} source files ({st.get('lines_analyzed', 0)} lines); "
        f"{st.get('secrets_redacted', 0)} secret-like value(s) were redacted before AI analysis",
        f"AI model: {asm.model}",
        "Every reported finding's quoted evidence was checked programmatically against the cited file and line",
        f"AI review candidates: {st.get('candidates', 0)}; dropped because evidence could not be verified: "
        f"{st.get('dropped_unverifiable', 0)}; rejected during lead review: {st.get('rejected_by_review', 0)}; "
        f"merged as duplicates: {st.get('merged_duplicates', 0)}",
    ]
    out += [f"Note: {w}" for w in asm.warnings]
    out += [f"Rejected candidate: {r['title']} ({r['file']}:{r['line']}): {r['reason']}" for r in asm.rejected]
    return out


def _overall(asm: Assessment) -> tuple[str, list[str], str]:
    head = f"Overall risk rating: {risk_rating(asm.findings)}."
    tail = "The report is an AI-assisted source-code assessment, not a complete penetration test."
    return head, asm.priorities, tail


# ----------------------------------------------------------------------- Markdown
def render_markdown(asm: Assessment) -> str:
    out = ["# Security Assessment Report", "",
           "## 1. Assessment Information", "",
           f"**Application:** {asm.app_name}", "",
           "**Assessment Type:** AI-Assisted Static Code Review", "",
           f"**Assessment Date:** {asm.date}", "",
           f"**Tool Name:** AegisReview v{asm.tool_version}", "",
           "## 2. Executive Summary", "", _exec_summary(asm), "",
           "## 3. Findings Summary", "", "| Severity | Count |", "|---|---:|"]
    out += [f"| {name} | {n} |" for name, n in _count_rows(asm.findings)]
    out += [f"| **Total** | **{len(asm.findings)}** |", "", "## 4. Detailed Findings", ""]
    if not asm.findings:
        out += ["No findings met the evidence bar in the analyzed source code.", ""]
    for i, f in enumerate(asm.findings, 1):
        lang = asm.languages.get(f.file, "")
        out += [f"### Finding {i}: {f.title}", "",
                f"**Finding ID:** {f.id}", "",
                f"**Severity:** {f.severity.capitalize()}", "",
                f"**Category:** {_category(f)}", "",
                f"**CWE:** {_cwe(f)}", "",
                f"**Affected File:** `{f.file}`", "",
                f"**Code Location:** {loc(f)}", "",
                "#### Description", "", f.description or "n/a", "",
                "#### Vulnerable Code", "", _fence(snippet(asm, f), lang), "",
                "#### Potential Impact", "", f.impact or "n/a", "",
                "#### Recommended Fix", "", f.remediation or "n/a", "",
                "#### Secure Code Example", "",
                _fence(f.secure_code, lang) if f.secure_code.strip() else NO_SNIPPET, "",
                "#### Confidence", "", _confidence(f), "",
                "#### Validation Notes", "", _validation(f), ""]
    out += ["## 5. Remediation Summary", "", "| Finding | Severity | Recommended Action |", "|---|---|---|"]
    out += [f"| {f.id} | {f.severity.capitalize()} | {_cell(_short_action(f))} |" for f in asm.findings]
    head, prios, tail = _overall(asm)
    out += ["", "## 6. Overall Assessment", "", head, "", asm.overall_assessment or "n/a", ""]
    if prios:
        out += ["Recommended order of work:", ""] + [f"{i}. {p}" for i, p in enumerate(prios, 1)] + [""]
    out += [tail, "", "## 7. Scope and Limitations", ""]
    out += [f"- {b}" for b in SCOPE_FIXED + _scope_extras(asm)]
    out += ["", "## 8. Conclusion", ""]
    for para in CONCLUSION:
        out += [para, ""]
    return "\n".join(out).rstrip() + "\n"


# ----------------------------------------------------------------------- HTML
def _e(x) -> str:
    return html.escape(str(x), quote=True)


def _p(text: str) -> str:
    return "<p>" + _e(text).replace("\n\n", "</p><p>").replace("\n", "<br>") + "</p>"


def render_html(asm: Assessment) -> str:
    h = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment: {_e(asm.app_name)}</title>
<style>
body{{font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;color:#0f172a;max-width:960px;margin:0 auto;padding:24px;background:#f8fafc}}
h1{{margin:0 0 4px}}h2{{margin-top:36px;border-bottom:2px solid #e2e8f0;padding-bottom:6px}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;margin:16px 0}}
.badge{{display:inline-block;color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;text-transform:uppercase}}
.fields p{{margin:4px 0}}
pre{{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:13px}}
.good pre{{background:#052e16}}table{{border-collapse:collapse;width:100%;background:#fff}}th,td{{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;font-size:14px}}
th{{background:#f1f5f9}}td:first-child,th:first-child{{white-space:nowrap}}code{{background:#e2e8f0;padding:1px 5px;border-radius:4px}}pre code{{background:none;padding:0}}
.sev{{max-width:360px}}.sev td:last-child,.sev th:last-child{{text-align:right}}
@media print{{body{{background:#fff}}.card{{break-inside:avoid}}}}
</style></head><body>
<h1>Security Assessment Report</h1>
<h2>1. Assessment Information</h2>
<div class="card fields"><p><b>Application:</b> {_e(asm.app_name)}</p>
<p><b>Assessment Type:</b> AI-Assisted Static Code Review</p>
<p><b>Assessment Date:</b> {_e(asm.date)}</p>
<p><b>Tool Name:</b> AegisReview v{_e(asm.tool_version)}</p></div>
<h2>2. Executive Summary</h2><div class="card">{_p(_exec_summary(asm))}</div>
<h2>3. Findings Summary</h2>
<table class="sev"><tr><th>Severity</th><th>Count</th></tr>"""]
    for name, n in _count_rows(asm.findings):
        h.append(f"<tr><td>{name}</td><td>{n}</td></tr>")
    h.append(f"<tr><td><b>Total</b></td><td><b>{len(asm.findings)}</b></td></tr></table>")
    h.append("<h2>4. Detailed Findings</h2>")
    if not asm.findings:
        h.append("<p>No findings met the evidence bar in the analyzed source code.</p>")
    for i, f in enumerate(asm.findings, 1):
        h.append(f'<div class="card" id="{_e(f.id)}"><h3><span class="badge" style="background:{SEV_COLOR[f.severity]}">{_e(f.severity)}</span> '
                 f'Finding {i}: {_e(f.title)}</h3><div class="fields">'
                 f'<p><b>Finding ID:</b> {_e(f.id)}</p><p><b>Severity:</b> {_e(f.severity.capitalize())}</p>'
                 f'<p><b>Category:</b> {_e(_category(f))}</p><p><b>CWE:</b> {_e(_cwe(f))}</p>'
                 f'<p><b>Affected File:</b> <code>{_e(f.file)}</code></p><p><b>Code Location:</b> {_e(loc(f))}</p></div>'
                 f'<h4>Description</h4>{_p(f.description or "n/a")}'
                 f'<h4>Vulnerable Code</h4><pre><code>{_e(snippet(asm, f))}</code></pre>'
                 f'<h4>Potential Impact</h4>{_p(f.impact or "n/a")}'
                 f'<h4>Recommended Fix</h4>{_p(f.remediation or "n/a")}')
        if f.secure_code.strip():
            h.append(f'<h4>Secure Code Example</h4><div class="good"><pre><code>{_e(f.secure_code)}</code></pre></div>')
        else:
            h.append(f"<h4>Secure Code Example</h4>{_p(NO_SNIPPET)}")
        h.append(f"<h4>Confidence</h4>{_p(_confidence(f))}<h4>Validation Notes</h4>{_p(_validation(f))}</div>")
    h.append("<h2>5. Remediation Summary</h2><table><tr><th>Finding</th><th>Severity</th><th>Recommended Action</th></tr>")
    for f in asm.findings:
        h.append(f"<tr><td>{_e(f.id)}</td><td>{_e(f.severity.capitalize())}</td><td>{_e(_short_action(f))}</td></tr>")
    head, prios, tail = _overall(asm)
    h.append("</table><h2>6. Overall Assessment</h2><div class='card'>" + _p(head) + _p(asm.overall_assessment or "n/a"))
    if prios:
        h.append("<p>Recommended order of work:</p><ol>" + "".join(f"<li>{_e(p)}</li>" for p in prios) + "</ol>")
    h.append(_p(tail) + "</div><h2>7. Scope and Limitations</h2><ul>"
             + "".join(f"<li>{_e(b)}</li>" for b in SCOPE_FIXED + _scope_extras(asm)) + "</ul>")
    h.append("<h2>8. Conclusion</h2>" + "".join(_p(c) for c in CONCLUSION) + "</body></html>")
    return "\n".join(h)


# ----------------------------------------------------------------------- JSON
def render_json(asm: Assessment) -> str:
    data = {
        "application": asm.app_name, "date": asm.date,
        "tool": {"name": "AegisReview", "version": asm.tool_version, "model": asm.model, "ai_used": asm.ai_used},
        "risk_rating": risk_rating(asm.findings), "executive_summary": asm.executive_summary,
        "overall_assessment": asm.overall_assessment, "top_priorities": asm.priorities,
        "severity_counts": severity_counts(asm.findings),
        "findings": [f.to_dict() for f in asm.findings],
        "rejected_candidates": asm.rejected, "stats": asm.stats, "warnings": asm.warnings,
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
