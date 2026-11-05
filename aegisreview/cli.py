"""Command line interface."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .collector import load_source
from .config import load_settings
from .models import SEV_RANK, SEVERITIES
from .prompts import LENSES
from .report import render_html, render_json, render_markdown, risk_rating, severity_counts

RENDERERS = {"md": ("md", render_markdown), "html": ("html", render_html), "json": ("json", render_json)}


def cmd_check(args) -> int:
    s = load_settings(args.env, args.model)
    from .ai import AIError, make_client
    try:
        client = make_client(s)
        out = client.generate_json("Reply with JSON only.", 'Return {"status":"ok"}', "check")
    except AIError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK: {client.label} model '{s.model}' responded: {out}")
    return 0


def cmd_scan(args) -> int:
    settings = load_settings(args.env, args.model)
    if args.no_cache:
        settings.cache_dir = None
    lenses = list(LENSES) if args.lenses == "all" else [x.strip() for x in args.lenses.split(",") if x.strip()]
    bad = [x for x in lenses if x not in LENSES]
    if bad:
        print(f"Unknown lens: {', '.join(bad)}. Available: {', '.join(LENSES)}", file=sys.stderr)
        return 2
    formats = [x.strip() for x in args.formats.split(",") if x.strip()]
    if any(f not in RENDERERS for f in formats):
        print("--formats accepts: md, html, json", file=sys.stderr)
        return 2
    try:
        tree = load_source(args.target, args.name)
    except (ValueError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    try:
        if not args.no_ai:
            print(f"Notice: source code (secret-like values redacted) will be sent to Anthropic Claude ({settings.model}). "
                  "Only analyze code you are authorized to share.", file=sys.stderr)
        asm = analyze(tree, settings, use_ai=not args.no_ai, lenses=lenses, max_batch_chars=args.max_batch_chars)
    finally:
        tree.cleanup()
    out_dir = Path(args.out).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", asm.app_name).strip("-") or "project"
    written = []
    for fmt in formats:
        ext, fn = RENDERERS[fmt]
        path = out_dir / f"{base}-security-report.{ext}"
        path.write_text(fn(asm), encoding="utf-8")
        written.append(path)
    c = severity_counts(asm.findings)
    print(f"\nAegisReview v{__version__}: {asm.app_name}")
    print(f"Risk rating: {risk_rating(asm.findings)}   Findings: {len(asm.findings)}  "
          + "  ".join(f"{s}={c[s]}" for s in SEVERITIES if c[s]))
    for f in asm.findings:
        print(f"  {f.id} [{f.severity:<8}] {f.title}  ({f.file}:{f.line_start})")
    for w in asm.warnings:
        print(f"  note: {w}")
    print("Reports:")
    for p in written:
        print(f"  {p}")
    if args.fail_on and any(SEV_RANK[f.severity] <= SEV_RANK[args.fail_on] for f in asm.findings):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegisreview", description="AI-powered security code review.")
    p.add_argument("--version", action="version", version=f"aegisreview {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="analyze a folder, ZIP file or git URL and write a security report")
    s.add_argument("target", help="path to a folder or .zip, or an https/git URL")
    s.add_argument("-o", "--out", default="reports", help="output directory (default: reports)")
    s.add_argument("--formats", default="md,html,json", help="comma list of: md, html, json")
    s.add_argument("--name", help="application name for the report")
    s.add_argument("--model", help="override ANTHROPIC_MODEL")
    s.add_argument("--env", help="path to a .env file")
    s.add_argument("--lenses", default="all", help=f"comma list of review passes (default all): {', '.join(LENSES)}")
    s.add_argument("--max-batch-chars", type=int, default=250_000, help="split very large projects into batches of this size")
    s.add_argument("--no-cache", action="store_true", help="do not reuse cached AI responses")
    s.add_argument("--no-ai", action="store_true", help="offline mode: pattern-based leads only (no code leaves the machine)")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit with code 1 if a finding at/above this severity exists")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("check", help="verify the API key and model name")
    c.add_argument("--model")
    c.add_argument("--env")
    c.set_defaults(func=cmd_check)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
