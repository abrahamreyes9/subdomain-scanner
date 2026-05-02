# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **SubDomainScout** — a passive subdomain reconnaissance web app. It discovers subdomains using passive OSINT sources and semi-active techniques (DNS brute-force, lightweight port scanning), then enriches each with IP/ASN/SSL/HTTP data. The primary codebase lives in the `webapp/` directory (which has its own git repo).

## Build & Run

```bash
# Activate venv (from repo root)
source .venv/Scripts/activate   # Windows Git Bash

# Install dependencies
pip install -r webapp/requirements.txt

# Run dev server (hot-reload)
cd webapp && python main.py
# → http://localhost:8000

# Docker
cd webapp && docker build -t scanner . && docker run -p 8000:8000 scanner
```

Environment variables: `SHODAN_API_KEY` (optional), config fields can be overridden via uppercase env vars (e.g. `MAX_WORKERS=64`). A `.env` file is loaded automatically.

## Architecture

The webapp follows a streaming pipeline pattern — scans run in a background thread, emit structured events into a `queue.Queue`, and the FastAPI server streams them to the browser via SSE.

**Key modules (all in `webapp/`):**

- **main.py** — FastAPI app. Three routes: `GET /` (serves SPA), `POST /api/scan` (starts scan, returns `scan_id`), `GET /api/stream/{scan_id}` (SSE event stream). Scans run in daemon threads.
- **scanner.py** — Orchestrates the scan phases (WHOIS → DNS → Passive sources → Brute-force → Permutations → Resolve → Enrich). Uses `ThreadPoolExecutor` for concurrency. Reads from `Config` and emits events via `ScanContext`.
- **subdomain_enum.py** (~2100 lines) — All recon logic: DNS enumeration, crt.sh/HackerTarget/Wayback fetching, WHOIS, HTTP probing, SSL inspection, nmap port scanning, subdomain takeover detection, Cloudflare detection, permutation generation. Also has a standalone CLI mode (`if __name__ == "__main__"`).
- **config.py** — `Config` dataclass with JSON file + env var loading. Controls thread pools, rate limits, timeouts, feature toggles (wayback, permutations, nmap, tech fingerprinting).
- **context.py** — `ScanContext`: thread-safe event emitter, progress tracking, cancellation via `threading.Event`.
- **utils.py** — Token-bucket DNS rate limiter (`TokenBucket`), retry decorator with exponential backoff.
- **output.py** — `OutputFormatter`: JSON/NDJSON/CSV export.
- **static/index.html** — Single-file SPA (vanilla HTML/CSS/JS) that consumes the SSE stream and renders results.

**Scan phases (in order):** WHOIS → DNS (NS, MX, TXT, SRV, AXFR zone transfer) → Passive (crt.sh, HackerTarget, Wayback) → Brute-force (common subdomains list) → Smart permutations → Resolve unresolved → Enrich (IP info, HTTP probe, SSL, rDNS, nmap, Shodan, takeover check).

**Event types on SSE stream:** `phase`, `status`, `warning`, `whois`, `dns`, `subdomain`, `progress`, `enriched`, `error`, `done`.

There is also a standalone version of the enumerator at `subdomain_enum.py` (repo root, ~1065 lines) — this is the original CLI-only script before the web app was built.

## Deployment

Deployed via Docker on Railway. Pushes to `main` in `webapp/` trigger automatic redeploy. The Dockerfile installs `nmap` in the container for port scanning.

## Other directories

- `abe/resume/` — Resume/CV generation scripts (unrelated to scanner)
- `recon/` — Separate recon tooling directory
