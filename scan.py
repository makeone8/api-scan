#!/usr/bin/env python3
"""API key scanner — detect exposed keys in files and GitHub repos."""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path

# ── Known API key patterns (name, file-scan regex, search query) ─────
PATTERNS = [
    ("AWS Access Key",       r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",       r"(?i)aws(.{0,20})?secret.{0,10}[\'\"]([0-9a-zA-Z/+]{40})[\'\"]"),
    ("GitHub PAT (classic)", r"ghp_[0-9a-zA-Z]{36}"),
    ("GitHub OAuth",         r"gho_[0-9a-zA-Z]{36}"),
    ("GitHub App",           r"ghu_[0-9a-zA-Z]{36}"),
    ("GitHub PAT (fine)",    r"github_pat_[0-9a-zA-Z_]{82}"),
    ("Google API Key",       r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth ID",      r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Stripe Live Key",      r"sk_live_[0-9a-zA-Z]{24,99}"),
    ("Stripe Test Key",      r"sk_test_[0-9a-zA-Z]{24,99}"),
    ("Slack Bot Token",      r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
    ("Slack Webhook",        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}"),
    ("Twilio API Key",       r"SK[0-9a-fA-F]{32}"),
    ("OpenAI Key",           r"sk-[a-zA-Z0-9]{32,99}"),
    ("Heroku API Key",       r"heroku[a-z0-9]{32}"),
    ("Generic JWT",          r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("Private Key header",   r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("GitLab Token",         r"glpat-[0-9a-zA-Z\-_]{20,}"),
    ("Azure Storage Key",    r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[a-zA-Z0-9+/=]{88}"),
]

# Distinctive substrings to search GitHub with
SEARCH_QUERIES = [
    ("AWS Access Key",     "AKIA"),
    ("Stripe Live Key",    "sk_live_"),
    ("Stripe Test Key",    "sk_test_"),
    ("Google API Key",     "AIza"),
    ("Slack Bot Token",    "xoxb-"),
    ("GitHub PAT",         "ghp_"),
    ("OpenAI Key",         "sk-proj-"),
    ("OpenAI Key (old)",   "sk-"),
    ("Private Key header", "BEGIN RSA PRIVATE KEY"),
    ("Private Key header", "BEGIN OPENSSH PRIVATE KEY"),
    ("Slack Webhook",      "hooks.slack.com/services/"),
]

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt", ".scala", ".clj",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".yaml", ".yml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".env.", ".properties", ".gradle", ".tf", ".tfvars",
    ".md", ".txt", ".rst", ".csv", ".log",
    ".html", ".htm", ".css", ".scss", ".less", ".vue", ".svelte",
    ".sql", ".graphql", ".proto",
    ".dockerfile", ".makefile", ".cmake",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    ".mypy_cache", ".pytest_cache", ".next", ".nuxt", "dist", "build",
    "target", ".idea", ".vscode", ".vs", "vendor", "bower_components",
    ".terraform", ".serverless",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
    "Gemfile.lock", "poetry.lock", "Pipfile.lock", "composer.lock",
    ".DS_Store", "Thumbs.db",
}

ENTROPY_THRESHOLD = 4.2
BASE64ISH_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,128}")

GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?$",
    re.IGNORECASE,
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def compile_patterns():
    return [(name, re.compile(p)) for name, p in PATTERNS]


def should_scan_file(filepath: str) -> bool:
    path = Path(filepath)
    ext = path.suffix.lower()
    name = path.name
    if name in SKIP_FILES:
        return False
    if ext in TEXT_EXTENSIONS:
        return True
    if ext == "":
        return True
    return False


def should_skip_dir(dirname: str) -> bool:
    return dirname in SKIP_DIRS or dirname.startswith(".")


class Finding:
    def __init__(self, filepath: str, line: int, name: str, match: str):
        self.filepath = filepath
        self.line = line
        self.name = name
        self.match = match


class SearchHit:
    def __init__(self, repo: str, path: str, name: str):
        self.repo = repo
        self.path = path
        self.name = name


def scan_file(filepath: str, patterns: list, scan_entropy: bool) -> list[Finding]:
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for name, regex in patterns:
            for m in regex.finditer(line):
                findings.append(Finding(filepath, lineno, name, m.group(0)))

        if scan_entropy:
            for m in BASE64ISH_RE.finditer(line):
                token = m.group(0)
                if is_likely_false_positive(token):
                    continue
                ent = shannon_entropy(token)
                if ent >= ENTROPY_THRESHOLD:
                    findings.append(
                        Finding(filepath, lineno, f"High-entropy (H={ent:.1f})", token)
                    )

    return findings


def is_likely_false_positive(token: str) -> bool:
    if len(set(token)) <= 3:
        return True
    if token == token[0] * len(token):
        return True
    if token.count("/") > 3 or token.count("\\") > 3:
        return True
    if token.count(".") >= 3 and all(part for part in token.split(".")):
        return True
    for period in range(2, min(len(token) // 2 + 1, 13)):
        if len(token) % period == 0:
            chunk = token[:period]
            if all(
                token[i : i + period] == chunk
                for i in range(0, len(token), period)
            ):
                return True
    return False


def scan_directory(root: str, patterns: list, scan_entropy: bool, exclude: set[str]) -> list[Finding]:
    findings = []
    exclude_toplevel = {e.lstrip("/\\").split(os.sep)[0] for e in exclude}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d) and d not in exclude_toplevel]
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""
        if any(
            rel_dir == e.lstrip("/\\") or rel_dir.startswith(e.lstrip("/\\") + os.sep)
            for e in exclude
        ):
            continue

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, root)
            if any(
                rel_path == e.lstrip("/\\") or rel_path.startswith(e.lstrip("/\\") + os.sep)
                for e in exclude
            ):
                continue
            if should_scan_file(filepath):
                findings.extend(scan_file(filepath, patterns, scan_entropy))
    return findings


def format_findings(findings: list[Finding], root: str) -> str:
    if not findings:
        return "\n[OK] No API keys found.\n"

    grouped = defaultdict(list)
    for f in findings:
        grouped[f.filepath].append(f)

    lines = [f"\n[!] Found {len(findings)} potential key(s) in {len(grouped)} file(s):\n"]
    for filepath, items in sorted(grouped.items()):
        try:
            rel = os.path.relpath(filepath, root)
        except ValueError:
            rel = filepath
        lines.append(f"  {rel}")
        for item in items:
            match_trunc = item.match if len(item.match) <= 100 else item.match[:97] + "..."
            lines.append(f"    L{item.line:4d}  [{item.name}]  {match_trunc}")
    return "\n".join(lines)


# ── GitHub search ────────────────────────────────────────────────────

def github_api_search(query: str, limit: int = 30, languages: list[str] | None = None,
                       token: str | None = None) -> list[SearchHit]:
    """Search GitHub code via the REST API."""
    q = query
    if languages:
        lang_filter = " ".join(f"language:{l}" for l in languages)
        q = f"{query} {lang_filter}"

    url = f"https://api.github.com/search/code?q={urllib.parse.quote(q)}&per_page={min(limit, 100)}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "api-key-scanner")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403 or e.code == 429:
            print(f"[!] GitHub API rate limit hit. Set GITHUB_TOKEN env var for higher limits.", file=sys.stderr)
        elif e.code == 422:
            # Unprocessable — query too broad or invalid
            return []
        else:
            print(f"[!] GitHub API error {e.code} for query '{query}'", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Search failed for '{query}': {e}", file=sys.stderr)
        return []

    hits = []
    for item in body.get("items", [])[:limit]:
        repo = item.get("repository", {}).get("full_name", "unknown")
        path = item.get("path", "")
        hits.append(SearchHit(repo, path, query))
    return hits


def run_github_search(queries: list[str] | None, limit: int,
                      lang: list[str] | None, token: str) -> dict[str, list[SearchHit]]:
    """Run search queries via GitHub REST API and return hits grouped by repo."""
    if queries is None:
        items = [(name, q) for name, q in SEARCH_QUERIES]
    else:
        items = [(q, q) for q in queries]

    all_hits: dict[str, list[SearchHit]] = defaultdict(list)

    for name, query in items:
        print(f"Searching: [{name}] \"{query}\" ...", end=" ", flush=True)
        hits = github_api_search(query, limit=limit, languages=lang, token=token)
        print(f"{len(hits)} result(s)")
        for h in hits:
            all_hits[h.repo].append(h)

    return all_hits


def format_search_results(hits_by_repo: dict[str, list[SearchHit]]) -> str:
    if not hits_by_repo:
        return "\n[OK] No results.\n"

    total = sum(len(v) for v in hits_by_repo.values())
    lines = [f"\n[!] {total} hit(s) across {len(hits_by_repo)} repo(s):\n"]

    for repo, hits in sorted(hits_by_repo.items(), key=lambda x: -len(x[1])):
        lines.append(f"  github.com/{repo}  ({len(hits)} hits)")
        shown = set()
        for h in hits:
            key = (h.path, h.name)
            if key not in shown:
                shown.add(key)
                lines.append(f"    [{h.name}]  {h.path}")

    return "\n".join(lines)


# ── Repo operations ──────────────────────────────────────────────────

def parse_github_url(url: str) -> tuple[str, str]:
    m = GITHUB_URL_RE.match(url.rstrip("/"))
    if m:
        return m.group(1), m.group(2)
    parts = url.strip("/").split("/")
    if len(parts) == 2 and "." not in parts[0] and "." not in parts[1].replace(".git", ""):
        return parts[0], parts[1].replace(".git", "")
    return "", ""


def clone_repo(owner: str, repo: str, branch: str | None, target_dir: str) -> str:
    repo_url = f"https://github.com/{owner}/{repo}.git"
    cmd = ["git", "clone", "--depth=1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([repo_url, target_dir])

    print(f"Cloning {owner}/{repo}...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error cloning repo:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"Cloned to {target_dir}\n")
    return target_dir


def scan_and_report(target: str, patterns: list, args, label: str = "") -> int:
    """Scan a target and print results. Returns number of findings."""
    if os.path.isfile(target):
        findings = scan_file(target, patterns, not args.no_entropy)
    elif os.path.isdir(target):
        findings = scan_directory(target, patterns, not args.no_entropy, set(args.exclude))
    else:
        print(f"Error: '{target}' not found", file=sys.stderr)
        return -1

    if args.json:
        output = []
        for f in findings:
            try:
                file_rel = os.path.relpath(f.filepath, target)
            except ValueError:
                file_rel = f.filepath
            output.append({
                "file": file_rel,
                "line": f.line,
                "type": f.name,
                "match": f.match,
            })
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        if label:
            print(f"\n── {label} ──")
        print(format_findings(findings, target))
        if not args.quiet and not label:
            print(f"Scanned: {target}")

    return len(findings)


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan files or GitHub repos for exposed API keys."
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help="Local path, GitHub URL, or (with --search) a custom search query"
    )
    parser.add_argument(
        "--search", "-s", action="store_true",
        help="Search GitHub for repos containing potential API keys"
    )
    parser.add_argument(
        "--token", "-t", default=None,
        help="GitHub personal access token (required for --search)"
    )
    parser.add_argument(
        "--scan-results", action="store_true",
        help="Clone and deep-scan repos found by --search"
    )
    parser.add_argument(
        "--limit", "-n", type=int, default=30,
        help="Max results per search query (default: 30)"
    )
    parser.add_argument(
        "--language", "-l", action="append", default=None,
        help="Language filter for search (e.g. python, javascript, can repeat)"
    )
    parser.add_argument(
        "--branch", "-b", default=None,
        help="Branch to scan (GitHub repos only)"
    )
    parser.add_argument(
        "--exclude", "-e", action="append", default=[],
        help="Path to exclude inside the scan target (can repeat)"
    )
    parser.add_argument(
        "--no-entropy", action="store_true",
        help="Skip high-entropy token scan"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON"
    )
    parser.add_argument(
        "--keep", action="store_true",
        help="Keep cloned repos after scan"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Only print findings, no summary"
    )
    args = parser.parse_args()

    patterns = compile_patterns()

    # ── Search mode ──
    if args.search:
        if not args.token:
            print("[!] --search requires --token <github_token>", file=sys.stderr)
            sys.exit(1)

        custom_queries = None
        if args.path != ".":
            custom_queries = [args.path]

        hits_by_repo = run_github_search(custom_queries, args.limit, args.language, args.token)
        if args.json:
            output = [
                {
                    "repo": repo,
                    "hits": [
                        {"path": h.path, "type": h.name}
                        for h in hits
                    ],
                }
                for repo, hits in sorted(hits_by_repo.items())
            ]
            print(json.dumps(output, indent=2, ensure_ascii=False))
        else:
            print(format_search_results(hits_by_repo))

        if args.scan_results and hits_by_repo:
            print("\n── Scanning found repos ──")
            total_findings = 0
            for repo in sorted(hits_by_repo.keys()):
                owner, repo_name = repo.split("/", 1)
                tmpdir = tempfile.mkdtemp(prefix=f"apiscan_{repo_name}_")
                clone_repo(owner, repo_name, args.branch, tmpdir)
                count = scan_and_report(tmpdir, patterns, args, label=repo)
                if count > 0:
                    total_findings += count
                if args.keep:
                    print(f"Kept clone at: {tmpdir}")
                else:
                    shutil.rmtree(tmpdir, ignore_errors=True)
            print(f"\nTotal: {total_findings} key(s) across all repos")

        sys.exit(0)

    # ── Single-target mode ──
    target = args.path
    cleanup_dir = None

    owner, repo = parse_github_url(target)
    is_github = bool(owner and repo)

    if is_github:
        tmpdir = tempfile.mkdtemp(prefix=f"apiscan_{repo}_")
        cleanup_dir = tmpdir
        target = clone_repo(owner, repo, args.branch, tmpdir)
        label = f"{owner}/{repo}" + (f" (branch: {args.branch})" if args.branch else "")
    else:
        target = os.path.abspath(target)
        label = ""

    count = scan_and_report(target, patterns, args, label=label)

    if cleanup_dir:
        if args.keep:
            print(f"Kept clone at: {target}")
        else:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    sys.exit(0 if count == 0 else 1)


if __name__ == "__main__":
    main()
