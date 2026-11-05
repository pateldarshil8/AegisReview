"""Review pipeline: redact -> AI review (parallel lenses) -> verify evidence -> AI consolidation."""
from __future__ import annotations

import concurrent.futures as cf
import json
import re
import sys
import time
from datetime import date

from . import __version__
from .ai import AIError, BaseClient, make_client
from .collector import SourceTree
from .config import Settings
from .hints import Hint, run_hints
from .models import SEV_RANK, Assessment, Finding
from .prompts import CONSOLIDATE_SYSTEM, LENSES, REVIEW_SYSTEM
from .redact import redact_text


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- prompt rendering
def _render_file(path: str, language: str, lines: list[str]) -> str:
    width = len(str(len(lines)))
    body = "\n".join(f"{i:>{width}}| {l}" for i, l in enumerate(lines, 1))
    body = body.replace("</source_file", "<‹/source_file").replace("<source_file", "<‹source_file")
    return f'<source_file path="{path}" language="{language}">\n{body}\n</source_file>'


def _make_batches(rendered: list[tuple[str, str]], max_chars: int) -> list[list[tuple[str, str]]]:
    batches, cur, size = [], [], 0
    for item in rendered:
        if cur and size + len(item[1]) > max_chars:
            batches.append(cur)
            cur, size = [], 0
        cur.append(item)
        size += len(item[1])
    if cur:
        batches.append(cur)
    return batches


def _review_prompt(name: str, all_paths: list[str], batch, lens_text: str, redaction_notes: list[str], hints: list[Hint]) -> str:
    parts = [f"Project: {name}", "", "All files in the project (some may be in other review batches):",
             "\n".join(f"- {p}" for p in all_paths), ""]
    if redaction_notes:
        parts += ["Redaction notes (secret-like values removed before sending):", "\n".join(redaction_notes[:60]), ""]
    batch_paths = {p for p, _ in batch}
    leads = [h for h in hints if h.file in batch_paths][:60]
    if leads:
        parts += ["Automated pattern leads (UNVERIFIED, may be false positives; confirm against the code or ignore):",
                  "\n".join(f"- {h.file}:{h.line} [{h.rule}] {h.snippet}" for h in leads), ""]
    parts += [lens_text, "", "SOURCE FILES:", "\n\n".join(r for _, r in batch)]
    return "\n".join(parts)


# ---------------------------------------------------------------- evidence verification
_LINE_PREFIX = re.compile(r"^\s*\d+\s*\|\s?")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def resolve_path(path: str, known: list[str]) -> str | None:
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    if p in known:
        return p
    cands = [k for k in known if k.endswith("/" + p) or p.endswith("/" + k)]
    return cands[0] if len(cands) == 1 else None


def locate_evidence(evidence: str, lines: list[str], claimed: int) -> tuple[int, int] | None:
    """Return 0-based (start, end) line indexes where the evidence appears, or None."""
    ev = [_norm(_LINE_PREFIX.sub("", l)) for l in evidence.splitlines()]
    ev = [e for e in ev if len(e) >= 3]
    if not ev:
        return None
    fl = [_norm(l) for l in lines]
    best = None  # (score, -distance, start, end)
    for k, e in enumerate(ev):
        for i, l in enumerate(fl):
            if not l or not (e in l or (len(l) >= 12 and l in e)):
                continue
            start = max(0, i - k)
            window = fl[start:start + len(ev) + 3]
            matched, last = 0, start
            for e2 in ev:
                for j, w in enumerate(window):
                    if w and (e2 in w or (len(w) >= 12 and w in e2)):
                        matched += 1
                        last = max(last, start + j)
                        break
            score = matched / len(ev)
            cand = (score, -abs((start + 1) - claimed) if claimed else 0, start, last)
            if best is None or cand[:2] > best[:2]:
                best = cand
    if best is None or best[0] < 0.5:
        return None
    start, end = best[2], best[3]
    return start, min(end, start + 14)


def verify_findings(findings: list[Finding], lines_by_file: dict[str, list[str]]):
    """Drop findings whose evidence cannot be found at the cited file; fix line numbers."""
    known = list(lines_by_file)
    kept, dropped = [], []
    for f in findings:
        path = resolve_path(f.file, known)
        if not path or not f.title:
            dropped.append((f, "cited file not found in the analyzed source"))
            continue
        f.file = path
        lines = lines_by_file[path]
        loc = locate_evidence(f.evidence, lines, f.line_start)
        if loc is None and "redacted" in f.evidence.lower() and 1 <= f.line_start <= len(lines):
            loc = (f.line_start - 1, max(f.line_start, f.line_end) - 1)
        if loc is None:
            dropped.append((f, "quoted evidence could not be found in the cited file"))
            continue
        f.line_start, f.line_end = loc[0] + 1, loc[1] + 1
        f.evidence = "\n".join(lines[loc[0]:loc[1] + 1])
        for r in f.related:
            rp = resolve_path(r["file"], known)
            r["file"] = rp or r["file"]
        f.related = [r for r in f.related if r["file"] in lines_by_file]
        kept.append(f)
    return kept, dropped


# ---------------------------------------------------------------- consolidation
def _context(lines: list[str], start: int, end: int, pad: int = 6, cap: int = 24) -> str:
    a, b = max(0, start - 1 - pad), min(len(lines), end + pad)
    b = min(b, a + cap)
    return "\n".join(f"{i + 1}| {lines[i]}" for i in range(a, b))


def _tokens(text: str) -> set:
    return set(re.findall(r"[a-z]{3,}", text.lower()))


def _same_defect(a: Finding, b: Finding) -> bool:
    if a.file != b.file or abs(a.line_start - b.line_start) > 6:
        return False
    if a.cwe and a.cwe == b.cwe:
        return True
    ta, tb = _tokens(a.title), _tokens(b.title)
    return bool(ta and tb) and len(ta & tb) / len(ta | tb) >= 0.3


def _heuristic_dedupe(findings: list[Finding]) -> list[Finding]:
    """Fallback when the AI lead review is unavailable: merge same-file, nearby, similar findings."""
    out: list[Finding] = []
    for f in sorted(findings, key=lambda x: SEV_RANK[x.severity]):
        t = next((o for o in out if _same_defect(o, f)), None)
        if t:
            t.related.append({"file": f.file, "line_start": f.line_start, "line_end": f.line_end, "note": f.title})
            t.related.extend(f.related)
            continue
        out.append(f)
    return out


def consolidate(client: BaseClient, name: str, cands: list[Finding], lines_by_file: dict):
    payload = []
    for c in cands:
        payload.append({
            "id": c.cid, "title": c.title, "category": c.category, "cwe": c.cwe, "severity": c.severity,
            "confidence": c.confidence, "status": c.status, "file": c.file,
            "line_start": c.line_start, "line_end": c.line_end, "lens": c.lens,
            "description": c.description[:500],
            "code_context": _context(lines_by_file[c.file], c.line_start, c.line_end),
        })
    prompt = f"Project: {name}\n\nCANDIDATE FINDINGS (JSON):\n{json.dumps(payload, indent=1)}"
    data = client.generate_json(CONSOLIDATE_SYSTEM, prompt, "consolidate")
    by_id = {c.cid: c for c in cands}
    decisions = {}
    for d in data.get("decisions") or []:
        if isinstance(d, dict) and d.get("id") in by_id:
            decisions.setdefault(d["id"], d)
    removed, rejected = set(), []
    for cid, d in decisions.items():
        if str(d.get("action", "keep")).lower() == "reject":
            c = by_id[cid]
            removed.add(cid)
            rejected.append({"title": c.title, "file": c.file, "line": c.line_start,
                             "reason": str(d.get("reason") or "judged unsupported by the lead reviewer")[:300]})
    for cid, d in decisions.items():
        if cid in removed:
            continue
        c = by_id[cid]
        if str(d.get("action", "keep")).lower() == "merge":
            t = by_id.get(d.get("merge_into"))
            if t and t.cid != cid and t.cid not in removed and str(decisions.get(t.cid, {}).get("action", "keep")).lower() != "merge":
                t.related.append({"file": c.file, "line_start": c.line_start, "line_end": c.line_end, "note": c.title})
                t.related.extend(c.related)
                removed.add(cid)
                continue
        probe = Finding.from_raw({"severity": d.get("severity"), "confidence": d.get("confidence"), "status": d.get("status")})
        if d.get("severity"):
            c.severity = probe.severity
        if d.get("confidence"):
            c.confidence = probe.confidence
        if d.get("status"):
            c.status = probe.status
    final = [c for c in cands if c.cid not in removed]
    prios = [str(p) for p in (data.get("top_priorities") or []) if str(p).strip()][:5]
    return final, rejected, str(data.get("executive_summary") or "").strip(), str(data.get("overall_assessment") or "").strip(), prios


# ---------------------------------------------------------------- fallback (no AI)
def heuristic_findings(hints: list[Hint]) -> list[Finding]:
    groups: dict[tuple, list[Hint]] = {}
    for h in hints:
        groups.setdefault((h.file, h.rule), []).append(h)
    out = []
    for (file, _rule), hs in groups.items():
        h = hs[0]
        out.append(Finding(
            title=h.title, category=h.category, cwe=h.cwe, owasp="", severity=h.severity,
            confidence="low", status="needs_validation", file=file, line_start=h.line, line_end=h.line,
            evidence=h.snippet, description=f"{h.note} This is a pattern match, not a confirmed vulnerability.",
            impact="Depends on whether untrusted input or an attacker-controlled path reaches this code.",
            remediation="Review this code manually, or re-run AegisReview with AI enabled for a contextual analysis and a tailored fix.",
            secure_code="", validation_notes="Pattern-based lead only; AI analysis was not applied.",
            related=[{"file": x.file, "line_start": x.line, "line_end": x.line, "note": x.snippet[:80]} for x in hs[1:6]],
            source="heuristic", lens="pattern-rules"))
    return out


# ---------------------------------------------------------------- main entry
def analyze(tree: SourceTree, settings: Settings, use_ai: bool = True, lenses: list[str] | None = None,
            max_batch_chars: int = 250_000) -> Assessment:
    lines_by_file: dict[str, list[str]] = {}
    languages: dict[str, str] = {}
    redaction_notes: list[str] = []
    redacted_files = []
    n_redactions = 0
    for f in tree.files:
        text, items = redact_text(f.text)
        n_redactions += len(items)
        for it in items:
            redaction_notes.append(f"- {f.path}:{it.line} {it.kind} (len={it.length}, placeholder-like={'yes' if it.placeholder_like else 'no'})")
        lines_by_file[f.path] = text.splitlines()
        languages[f.path] = f.language
        redacted_files.append(type("F", (), {"path": f.path, "language": f.language, "text": text}))
    hints = run_hints(redacted_files)
    total_lines = sum(len(v) for v in lines_by_file.values())
    asm = Assessment(app_name=tree.name, date=date.today().isoformat(), tool_version=__version__,
                     model=settings.model if use_ai else "none (pattern rules only)", ai_used=False,
                     file_lines=lines_by_file, languages=languages)
    asm.stats = {"files_analyzed": len(tree.files), "lines_analyzed": total_lines, "secrets_redacted": n_redactions,
                 "files_skipped": len(tree.skipped), "ai_calls": 0, "ai_calls_failed": 0, "candidates": 0,
                 "dropped_unverifiable": 0, "rejected_by_review": 0}
    if not tree.files:
        asm.warnings.append("No supported source files were found in the target.")
        return asm

    client = None
    if use_ai:
        try:
            client = make_client(settings)
        except AIError as e:
            asm.warnings.append(f"AI unavailable: {e}. Showing pattern-based leads only.")
    if client is None:
        asm.findings = _finalize(heuristic_findings(hints))
        asm.executive_summary = ("AI analysis was not performed. The items below are pattern-based leads that need manual validation; "
                                 "they are not confirmed vulnerabilities.")
        asm.overall_assessment = "Re-run with a valid API key for a contextual, evidence-verified assessment."
        return asm

    # ---- pass 1: independent AI reviews (batches x lenses)
    all_paths = [f.path for f in tree.files]
    rendered = [(f.path, _render_file(f.path, f.language, lines_by_file[f.path])) for f in tree.files]
    batches = _make_batches(rendered, max_batch_chars)
    lens_names = lenses or list(LENSES)
    tasks = [(bi, ln) for bi in range(len(batches)) for ln in lens_names]
    _log(f"Reviewing {len(tree.files)} files ({total_lines} lines) with {settings.model}: {len(tasks)} AI review call(s)...")
    candidates: list[Finding] = []
    failures = 0
    asm.stats["ai_calls"] = len(tasks) + 1

    def run(task):
        bi, ln = task
        prompt = _review_prompt(tree.name, all_paths, batches[bi], LENSES[ln], redaction_notes, hints)
        data = client.generate_json(REVIEW_SYSTEM, prompt, f"review:{ln}")
        raw = data.get("findings") if isinstance(data, dict) else None
        return ln, [Finding.from_raw(r, ln) for r in (raw or []) if isinstance(r, dict)]

    failed_tasks = []
    with cf.ThreadPoolExecutor(max_workers=settings.concurrency) as pool:
        futures = []
        for t in tasks:
            futures.append((t, pool.submit(run, t)))
            time.sleep(settings.delay)
        for t, fut in futures:
            try:
                ln, found = fut.result()
                _log(f"  [{ln}] {len(found)} candidate(s)")
                candidates.extend(found)
            except AIError as e:
                failed_tasks.append(t)
                _log(f"  review call failed: {e}")
    for t in failed_tasks:  # one more chance, sequentially, after the service has had time to recover
        _log(f"  retrying failed pass [{t[1]}]...")
        time.sleep(15)
        try:
            ln, found = run(t)
            _log(f"  [{ln}] {len(found)} candidate(s)")
            candidates.extend(found)
        except AIError as e:
            failures += 1
            _log(f"  review call failed again: {e}")
    asm.stats["ai_calls_failed"] = failures
    asm.model = _models_label(client, settings)
    if failures == len(tasks):
        asm.warnings.append("All AI review calls failed. Showing pattern-based leads only.")
        asm.findings = _finalize(heuristic_findings(hints))
        asm.executive_summary = "AI analysis could not be completed; the items below are unverified pattern-based leads."
        asm.overall_assessment = "Check the API key, model name and network access, then re-run."
        return asm
    if failures:
        asm.warnings.append(f"{failures} of {len(tasks)} AI review calls failed; coverage may be incomplete.")
    asm.ai_used = True

    # ---- verify evidence
    asm.stats["candidates"] = len(candidates)
    verified, dropped = verify_findings(candidates, lines_by_file)
    asm.stats["dropped_unverifiable"] = len(dropped)
    for i, f in enumerate(verified, 1):
        f.cid = f"C{i}"

    # ---- pass 2: lead-reviewer consolidation
    final, summary, overall, prios = verified, "", "", []
    if verified:
        try:
            _log(f"Consolidating {len(verified)} verified candidate(s)...")
            final, rejected, summary, overall, prios = consolidate(client, tree.name, verified, lines_by_file)
            asm.rejected = rejected
            asm.stats["rejected_by_review"] = len(rejected)
        except AIError as e:
            asm.stats["ai_calls_failed"] += 1
            asm.warnings.append(f"Consolidation step failed ({e}); applied rule-based de-duplication instead.")
            final = _heuristic_dedupe(verified)
        asm.model = _models_label(client, settings)
    asm.findings = _finalize(final)
    asm.stats["merged_duplicates"] = max(0, len(verified) - len(asm.findings) - len(asm.rejected))
    asm.executive_summary = summary or _default_summary(asm.findings)
    asm.overall_assessment = overall or _default_overall(asm.findings)
    asm.priorities = prios
    return asm


def _models_label(client: BaseClient, settings: Settings) -> str:
    names = [m for m, _ in client.used.most_common()]
    label = ", ".join(names) if names else client.label
    return f"{label} (some responses reused from cache)" if client.cache_hits else label


def _tidy_related(f: Finding) -> None:
    """Drop repeated locations and 'related' entries that merely restate the primary finding."""
    seen, out = {(f.file, f.line_start)}, []
    primary_tokens = _tokens(f.title)
    for r in f.related:
        key = (r["file"], r["line_start"])
        if key in seen:
            continue
        seen.add(key)
        near = r["file"] == f.file and f.line_start - 4 <= r["line_start"] <= f.line_end + 4
        note_tokens = _tokens(r.get("note", ""))
        similar = bool(primary_tokens and note_tokens) and len(primary_tokens & note_tokens) / len(primary_tokens | note_tokens) >= 0.5
        if near and similar:
            continue
        if any(o["file"] == r["file"] and abs(o["line_start"] - r["line_start"]) <= 2 for o in out):
            continue
        out.append(r)
    f.related = out


def _finalize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        _tidy_related(f)
    findings = sorted(findings, key=lambda f: (SEV_RANK[f.severity], f.file, f.line_start))
    for i, f in enumerate(findings, 1):
        f.id = f"AR-{i:03d}"
    return findings


def _default_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No security weaknesses met the evidence bar in the analyzed source code."
    top = findings[0]
    return (f"The review produced findings that need developer attention. The most severe issue is "
            f"\"{top.title}\" ({top.severity}). See the detailed findings below.")


def _default_overall(findings: list[Finding]) -> str:
    return "Address the highest-severity findings first, then re-run the review to confirm the fixes."
