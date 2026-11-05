"""Render an Assessment as Markdown, self-contained HTML, and JSON."""
from __future__ import annotations

import html
import json
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
        return "\n".join(lines[a:b])
    return f.evidence


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


# ----------------------------------------------------------------------- Markdown
def render_markdown(asm: Assessment) -> str:
    c = severity_counts(asm.findings)
    out = ["# Security Assessment Report", "",
           "## 1. Assessment Information", "",
           f"**Application:** {asm.app_name}", "",
           "**Assessment Type:** AI-Assisted Static Code Review", "",
           f"**Assessment Date:** {asm.date}", "",
           f"**Tool Name:** AegisReview v{asm.tool_version}", "",
           f"**AI Model:** {asm.model}", "",
           f"**Overall Risk Rating:** {risk_rating(asm.findings)}", "",
           "## 2. Executive Summary", "", asm.executive_summary or "No summary available.", ""]
    if asm.priorities:
        out += ["**Top priorities**", ""] + [f"{i}. {p}" for i, p in enumerate(asm.priorities, 1)] + [""]
    for w in asm.warnings:
        out += [f"> Note: {w}", ""]
    out += ["## 3. Findings Summary", "", "| Severity | Count |", "|---|---:|"]
    out += [f"| {s.capitalize()} | {c[s]} |" for s in SEVERITIES]
    out += [f"| **Total** | **{len(asm.findings)}** |", ""]
    if asm.findings:
        out += ["| ID | Severity | Title | Location | Status |", "|---|---|---|---|---|"]
        for f in asm.findings:
            out.append(f"| {f.id} | {f.severity.capitalize()} | {_cell(f.title)} | `{f.file}` {loc(f)} | {STATUS_LABEL[f.status]} |")
        out.append("")
    out += ["## 4. Detailed Findings", ""]
    if not asm.findings:
        out += ["No findings met the evidence bar in the analyzed source code.", ""]
    for f in asm.findings:
        lang = asm.languages.get(f.file, "")
        out += [f"### {f.id}: {f.title}", "",
                f"**Severity:** {f.severity.capitalize()}  ", f"**Category:** {f.category or 'n/a'}  ",
                f"**CWE:** {f.cwe or 'n/a'}  ", f"**OWASP:** {f.owasp or 'n/a'}  ",
                f"**Affected File:** `{f.file}`  ", f"**Code Location:** {loc(f)}  ",
                f"**Status:** {STATUS_LABEL[f.status]}  ", f"**Confidence:** {f.confidence.capitalize()}", "",
                "#### Description", "", f.description or "n/a", "",
                "#### Vulnerable Code", "", _fence(snippet(asm, f), lang), "",
                "#### Potential Impact", "", f.impact or "n/a", "",
                "#### Recommended Fix", "", f.remediation or "n/a", ""]
        if f.secure_code.strip():
            out += ["#### Secure Code Example", "", _fence(f.secure_code, lang), ""]
        if f.validation_notes:
            out += ["#### Validation Notes", "", f.validation_notes, ""]
        rel = _related(f)
        if rel:
            out += ["#### Related Locations", ""] + [f"- {r}" for r in rel] + [""]
    out += ["## 5. Remediation Summary", ""]
    if asm.findings:
        out += ["| Finding | Severity | Recommended Action |", "|---|---|---|"]
        for f in asm.findings:
            first = f.remediation.split(". ")[0].rstrip(".") if f.remediation else "Review"
            out.append(f"| {f.id} | {f.severity.capitalize()} | {_cell(first)} |")
    else:
        out.append("No remediation required for the analyzed scope.")
    out += ["", "## 6. Overall Assessment", "", asm.overall_assessment or "n/a", "",
            "## 7. Scope and Limitations", "",
            "- Static code review only; no exploit execution or runtime testing",
            "- AI-generated findings should be validated before being treated as confirmed vulnerabilities",
            "- Every reported finding's quoted evidence was checked programmatically against the cited file and line",
            "- No guarantee that every vulnerability was found",
            f"- Files analyzed: {asm.stats.get('files_analyzed', 0)} ({asm.stats.get('lines_analyzed', 0)} lines)",
            f"- Secret-like values redacted before AI analysis: {asm.stats.get('secrets_redacted', 0)}",
            f"- AI review candidates: {asm.stats.get('candidates', 0)}; dropped because evidence could not be verified: "
            f"{asm.stats.get('dropped_unverifiable', 0)}; rejected during lead review: {asm.stats.get('rejected_by_review', 0)}", ""]
    if asm.rejected:
        out += ["### Candidates rejected during review", "", "| Candidate | Location | Reason |", "|---|---|---|"]
        for r in asm.rejected:
            out.append(f"| {_cell(r['title'])} | `{r['file']}`:{r['line']} | {_cell(r['reason'])} |")
        out.append("")
    out += ["## 8. Conclusion", "",
            "Address high-impact issues first and validate each remediation with appropriate testing. "
            "A follow-up review is recommended after the changes are applied.", ""]
    return "\n".join(out)


# ----------------------------------------------------------------------- HTML
def _e(x) -> str:
    return html.escape(str(x), quote=True)


def render_html(asm: Assessment) -> str:
    c = severity_counts(asm.findings)
    h = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment: {_e(asm.app_name)}</title>
<style>
body{{font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;color:#0f172a;max-width:960px;margin:0 auto;padding:24px;background:#f8fafc}}
h1{{margin:0 0 4px}}h2{{margin-top:36px;border-bottom:2px solid #e2e8f0;padding-bottom:6px}}
.meta{{color:#475569}}.card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;margin:16px 0}}
.badge{{display:inline-block;color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;text-transform:uppercase}}
.pill{{display:inline-block;background:#e2e8f0;border-radius:6px;padding:1px 8px;font-size:12px;margin-right:6px}}
.counts{{display:flex;gap:10px;flex-wrap:wrap}}.counts div{{flex:1;min-width:100px;text-align:center;border-radius:10px;color:#fff;padding:10px}}
.counts b{{display:block;font-size:26px}}
pre{{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:13px}}
.good pre{{background:#052e16}}table{{border-collapse:collapse;width:100%;background:#fff}}th,td{{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;font-size:14px}}
th{{background:#f1f5f9}}code{{background:#e2e8f0;padding:1px 5px;border-radius:4px}}pre code{{background:none;padding:0}}
.note{{background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:8px 12px;margin:10px 0}}
@media print{{body{{background:#fff}}.card{{break-inside:avoid}}}}
</style></head><body>
<h1>Security Assessment Report</h1>
<p class="meta"><b>{_e(asm.app_name)}</b> &middot; AI-assisted static code review &middot; {_e(asm.date)} &middot;
AegisReview v{_e(asm.tool_version)} &middot; model: {_e(asm.model)}</p>
<div class="card"><b>Overall risk rating: {_e(risk_rating(asm.findings))}</b></div>
<h2>Executive Summary</h2><div class="card"><p>{_e(asm.executive_summary or 'No summary available.')}</p>"""]
    if asm.priorities:
        h.append("<b>Top priorities</b><ol>" + "".join(f"<li>{_e(p)}</li>" for p in asm.priorities) + "</ol>")
    h.append("</div>")
    for w in asm.warnings:
        h.append(f'<div class="note">Note: {_e(w)}</div>')
    h.append('<h2>Findings Summary</h2><div class="counts">')
    for s in SEVERITIES:
        h.append(f'<div style="background:{SEV_COLOR[s]}"><b>{c[s]}</b>{s.capitalize()}</div>')
    h.append("</div>")
    if asm.findings:
        h.append("<table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Location</th><th>Status</th></tr>")
        for f in asm.findings:
            h.append(f'<tr><td><a href="#{_e(f.id)}">{_e(f.id)}</a></td><td>{_e(f.severity.capitalize())}</td><td>{_e(f.title)}</td>'
                     f'<td><code>{_e(f.file)}</code> {_e(loc(f))}</td><td>{_e(STATUS_LABEL[f.status])}</td></tr>')
        h.append("</table>")
    h.append("<h2>Detailed Findings</h2>")
    if not asm.findings:
        h.append("<p>No findings met the evidence bar in the analyzed source code.</p>")
    for f in asm.findings:
        h.append(f'<div class="card" id="{_e(f.id)}"><h3><span class="badge" style="background:{SEV_COLOR[f.severity]}">{_e(f.severity)}</span> '
                 f'{_e(f.id)}: {_e(f.title)}</h3>'
                 f'<p><span class="pill">{_e(f.category or "n/a")}</span><span class="pill">{_e(f.cwe or "n/a")}</span>'
                 f'<span class="pill">{_e(f.owasp or "OWASP n/a")}</span><span class="pill">{_e(STATUS_LABEL[f.status])}</span>'
                 f'<span class="pill">confidence: {_e(f.confidence)}</span></p>'
                 f'<p><b>Affected file:</b> <code>{_e(f.file)}</code> ({_e(loc(f))})</p>'
                 f'<h4>Description</h4><p>{_e(f.description)}</p>'
                 f'<h4>Vulnerable code</h4><pre><code>{_e(snippet(asm, f))}</code></pre>'
                 f'<h4>Potential impact</h4><p>{_e(f.impact)}</p>'
                 f'<h4>Recommended fix</h4><p>{_e(f.remediation)}</p>')
        if f.secure_code.strip():
            h.append(f'<div class="good"><h4>Secure code example</h4><pre><code>{_e(f.secure_code)}</code></pre></div>')
        if f.validation_notes:
            h.append(f"<h4>Validation notes</h4><p>{_e(f.validation_notes)}</p>")
        rel = _related(f)
        if rel:
            h.append("<h4>Related locations</h4><ul>" + "".join(f"<li>{r.replace('`', '')}</li>" for r in map(_e, rel)) + "</ul>")
        h.append("</div>")
    h.append("<h2>Remediation Summary</h2>")
    if asm.findings:
        h.append("<table><tr><th>Finding</th><th>Severity</th><th>Recommended action</th></tr>")
        for f in asm.findings:
            first = f.remediation.split(". ")[0].rstrip(".") if f.remediation else "Review"
            h.append(f"<tr><td>{_e(f.id)}</td><td>{_e(f.severity.capitalize())}</td><td>{_e(first)}</td></tr>")
        h.append("</table>")
    h.append(f"<h2>Overall Assessment</h2><div class='card'><p>{_e(asm.overall_assessment or 'n/a').replace(chr(10), '<br>')}</p></div>")
    h.append("<h2>Scope and Limitations</h2><ul>"
             "<li>Static code review only; no exploit execution or runtime testing</li>"
             "<li>AI-generated findings should be validated before being treated as confirmed vulnerabilities</li>"
             "<li>Every reported finding's quoted evidence was checked programmatically against the cited file and line</li>"
             "<li>No guarantee that every vulnerability was found</li>"
             f"<li>Files analyzed: {asm.stats.get('files_analyzed', 0)} ({asm.stats.get('lines_analyzed', 0)} lines); "
             f"secret-like values redacted before AI analysis: {asm.stats.get('secrets_redacted', 0)}</li>"
             f"<li>AI candidates: {asm.stats.get('candidates', 0)}; dropped (evidence not verifiable): {asm.stats.get('dropped_unverifiable', 0)}; "
             f"rejected during lead review: {asm.stats.get('rejected_by_review', 0)}</li></ul>")
    if asm.rejected:
        h.append("<h3>Candidates rejected during review</h3><table><tr><th>Candidate</th><th>Location</th><th>Reason</th></tr>")
        for r in asm.rejected:
            h.append(f"<tr><td>{_e(r['title'])}</td><td><code>{_e(r['file'])}</code>:{_e(r['line'])}</td><td>{_e(r['reason'])}</td></tr>")
        h.append("</table>")
    h.append("<h2>Conclusion</h2><p>Address high-impact issues first and validate each remediation with appropriate testing. "
             "A follow-up review is recommended after the changes are applied.</p></body></html>")
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
