# API Key Scanner

Scan local files or GitHub repositories for exposed API keys (AWS, Stripe, GitHub, OpenAI, Slack, etc.).

## Usage

```bash
# Scan current directory
python scan.py

# Scan a specific directory
python scan.py /path/to/project

# Scan a single file
python scan.py config.json

# Scan a GitHub repository
python scan.py https://github.com/user/repo
python scan.py user/repo -b develop     # specific branch

# Exclude paths
python scan.py . -e vendor -e dist

# JSON output
python scan.py . --json

# Skip high-entropy detection (pattern matching only)
python scan.py . --no-entropy
```

## GitHub Search

Search GitHub for repos containing potential API keys:

```bash
# Search with all default patterns
python scan.py --search

# Custom search query
python scan.py --search "AKIA" --limit 50

# Filter by language
python scan.py --search -l python -l javascript

# Search and deep-scan found repos
python scan.py --search --scan-results
```

GitHub search requires authentication — set `GITHUB_TOKEN` env var or install `gh` CLI.

## Supported Key Types

AWS, GitHub, Google, Stripe, Slack, Twilio, OpenAI, Heroku, GitLab, Azure, generic JWT, private key headers.

Also detects high-entropy strings (Base64-like tokens) as unknown key formats.

## Requirements

Python 3.10+. No external dependencies.
