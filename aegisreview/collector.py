"""Turn a folder, ZIP archive or git URL into a list of source files to review."""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", ".nuxt", "out", "coverage",
    ".venv", "venv", "env", "__pycache__", ".idea", ".vscode", "vendor", "target",
    ".gradle", ".terraform", ".cache", ".turbo", ".svelte-kit", "bower_components",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
    "composer.lock", "Gemfile.lock", "go.sum", "Pipfile.lock", "bun.lockb",
}
LANGUAGES = {
    ".ts": "typescript", ".tsx": "tsx", ".js": "javascript", ".jsx": "jsx",
    ".mjs": "javascript", ".cjs": "javascript", ".py": "python", ".java": "java",
    ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust",
    ".kt": "kotlin", ".swift": "swift", ".sql": "sql", ".sh": "bash",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
    ".html": "html", ".tf": "hcl", ".gradle": "groovy", ".xml": "xml",
    ".vue": "vue", ".svelte": "svelte", ".c": "c", ".cpp": "cpp", ".h": "c",
}
MAX_FILE_BYTES = 200_000
MAX_ZIP_BYTES = 200 * 1024 * 1024


@dataclass
class SourceFile:
    path: str  # POSIX path relative to the project root
    language: str
    text: str


@dataclass
class SourceTree:
    name: str
    root: Path
    files: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    _tmp: Path | None = None

    def cleanup(self) -> None:
        if self._tmp and self._tmp.exists():
            shutil.rmtree(self._tmp, ignore_errors=True)


def _language_for(path: Path) -> str | None:
    name = path.name
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "dockerfile"
    if name.startswith(".env"):
        return "dotenv"
    return LANGUAGES.get(path.suffix.lower())


def _safe_extract(zip_path: Path, dest: Path) -> None:
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            total += info.file_size
            if total > MAX_ZIP_BYTES:
                raise ValueError("ZIP archive is too large to analyze safely")
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError(f"Unsafe path in ZIP archive: {info.filename}")
        zf.extractall(dest)


def _single_child_dir(path: Path) -> Path:
    children = [c for c in path.iterdir() if not c.name.startswith("__MACOSX")]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return path


def _walk(root: Path, name: str, tmp: Path | None) -> SourceTree:
    tree = SourceTree(name=name, root=root, _tmp=tmp)
    for p in sorted(root.rglob("*")):
        rel_parts = p.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if p.is_dir() or p.is_symlink():
            continue
        rel = "/".join(rel_parts)
        if p.name in SKIP_FILES:
            tree.skipped.append((rel, "lockfile"))
            continue
        lang = _language_for(p)
        if lang is None:
            continue
        try:
            size = p.stat().st_size
            if size > MAX_FILE_BYTES:
                tree.skipped.append((rel, "too large"))
                continue
            data = p.read_bytes()
            if b"\x00" in data:
                tree.skipped.append((rel, "binary"))
                continue
            text = data.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            tree.skipped.append((rel, "unreadable"))
            continue
        if not text.strip():
            continue
        tree.files.append(SourceFile(rel, lang, text))
    return tree


def load_source(target: str, name: str | None = None) -> SourceTree:
    """Accepts a directory, a .zip file, or a git URL (https://... or git@...)."""
    if re.match(r"^(https?://|git@)", target):
        tmp = Path(tempfile.mkdtemp(prefix="aegisreview-"))
        dest = tmp / "repo"
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", target, str(dest)],
            capture_output=True, text=True, timeout=180,
        )
        if proc.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ValueError(f"git clone failed: {proc.stderr.strip()[:300]}")
        repo_name = name or target.rstrip("/").split("/")[-1].removesuffix(".git")
        return _walk(dest, repo_name, tmp)

    path = Path(target).expanduser()
    if not path.exists():
        raise ValueError(f"Path not found: {target}")
    if path.is_file() and path.suffix.lower() == ".zip":
        tmp = Path(tempfile.mkdtemp(prefix="aegisreview-"))
        _safe_extract(path, tmp)
        root = _single_child_dir(tmp)
        return _walk(root, name or path.stem, tmp)
    if path.is_dir():
        return _walk(path.resolve(), name or path.resolve().name, None)
    raise ValueError("Target must be a directory, a .zip file, or a git URL")
