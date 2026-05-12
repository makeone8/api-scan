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
python scan.py user/repo -b develop      # specific branch

# Scan with options
python scan.py . -e vendor -e dist        # exclude paths
python scan.py . --json                   # JSON output
python scan.py . --no-entropy             # skip high-entropy detection
```

## GitHub Search

Search GitHub for repos containing potential API keys.

```bash
# Quick search (all 11 default patterns)
python scan.py --search -t ghp_xxxxxxxxxxxx

# Custom query
python scan.py --search "AKIA" -t ghp_xxxxxxxxxxxx

# Tune search behavior
python scan.py --search -t ghp_xxxxxxxxxxxx \
    -l python -l javascript \              # language filter
    --limit 50 \                           # results per query
    --delay 6 \                            # delay between queries (seconds)
    --max-retries 5                        # retry on rate limit

# Search then clone + deep-scan each repo
python scan.py --search --scan-results -t ghp_xxxxxxxxxxxx
```

GitHub search requires a personal access token via `-t` / `--token`. Rate-limited queries are automatically retried with exponential backoff (configurable via `--max-retries`).

## Supported Key Types

AWS, GitHub, Google, Stripe, Slack, Twilio, OpenAI, Heroku, GitLab, Azure, generic JWT, private key headers.

Also detects high-entropy strings (Base64-like tokens) as unknown key formats.

## Requirements

Python 3.10+. No external dependencies.
