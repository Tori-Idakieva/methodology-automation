# OWASP WSTG Security Scanner

A Python-based web vulnerability scanner aligned with the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/). Combines HTTP-level testing with Playwright browser automation to detect XSS, SQL injection, missing security headers, and directory listing exposure.

---

## Overview

The scanner operates in five stages:

1. **Crawl** — Discovers URLs using both an HTTP crawler and a headless Chromium browser, capturing JavaScript-rendered content and dynamic routes.
2. **Detect** — Injects payloads and analyses responses across all discovered URLs and forms for XSS, SQLi, header weaknesses, and directory listing.
3. **Integrate** — Optionally invokes sqlmap and Nikto for deeper, specialised testing.
4. **Enrich** — Queries the NVD CVE API 2.0 to annotate each finding with its CWE ID, OWASP WSTG reference, CVE count, and CVSS score.
5. **Report** — Writes an HTML and/or JSON report and prints a colour-coded terminal summary.

### Two-crawler approach

The **HTTP crawler** (`http_crawler.py`) uses `requests` and `BeautifulSoup` to fetch pages and extract links without executing JavaScript — fast and lightweight.

The **browser crawler** (`browser_crawler.py`) uses Playwright to navigate in a real headless browser. It executes JavaScript, handles client-side routing, submits login forms, captures screenshots, and listens for `alert`/`confirm`/`prompt` dialogs as XSS confirmation signals.

Both crawlers produce a merged list of URLs and form injection vectors that the detectors consume.

### Authentication

- **Credentials** (`--username` / `--password`) — the browser crawler detects and submits the login form before crawling.
- **Session cookie** (`--auth-cookie`) — injects a pre-existing cookie into both the HTTP session and the browser context, bypassing login entirely.

---

## Project Structure

```
Dockerfile              # Scanner image (Python + Chromium + sqlmap + Nikto)
docker-compose.yml      # DVWA + scanner + optional Juice Shop
scripts/
  setup-dvwa.sh         # Automated DVWA database init + security level setup
scanner/
  main.py               # Entry point — orchestrates the full pipeline
  cli.py                # Argument parsing
  config.py             # Central configuration (timeouts, limits, defaults)
  http_crawler.py       # HTTP crawler (requests + BeautifulSoup)
  browser_crawler.py    # Playwright browser crawler
  payloads.py           # Injection payload and signature library
  detectors/
    xss.py              # XSS detector (WSTG-INPV-01)
    sqli.py             # SQL Injection detector (WSTG-INPV-05)
    headers.py          # Security header analyser (WSTG-CONF-07)
    dir_listing.py      # Directory listing detector (WSTG-CONF-04)
  integrations/
    nvd_api.py          # NVD CVE API 2.0 enrichment
    sqlmap_runner.py    # sqlmap subprocess wrapper (--use-sqlmap)
    nikto_runner.py     # Nikto subprocess wrapper (--use-nikto)
  reporting/
    html_report.py      # Styled self-contained HTML report
    json_report.py      # Machine-readable JSON report
    summary.py          # Colour-coded terminal summary
  utils/                # Shared helpers: HTTP session, URL utils, logging
  requirements.txt
```

---

## Prerequisites

**Docker (recommended):** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (macOS, Windows) or [Docker Engine](https://docs.docker.com/engine/install/) (Linux). No other dependencies needed — Python, Chromium, sqlmap, and Nikto are all bundled in the image.

**Local install (alternative):** Python 3.9+, pip.

---

## Quick Start with Docker Compose

Docker Compose is the recommended way to run the scanner against DVWA. Everything runs in containers on a shared internal network — no manual browser setup required.

### Step 1 — Build the scanner image

Run this once from the repository root:

```bash
docker compose build scanner
```

You do not need to rebuild after editing scanner code. The compose file mounts `scanner/` as a live bind mount so code changes are picked up immediately. Only rebuild when you change `requirements.txt` or `Dockerfile`.

### Step 2 — Start DVWA

```bash
docker compose up -d dvwa dvwa-setup
```

`dvwa-setup` is a one-shot container that initialises the DVWA database and sets the security level to Low automatically — no manual browser steps required. Follow its progress:

```bash
docker compose logs -f dvwa-setup
```

Wait until you see `[setup-dvwa] Setup complete. DVWA is ready to scan.`

DVWA is also accessible in your browser at http://localhost:42001 (credentials: `admin` / `password`).

### Step 3 — Run the scanner

```bash
docker compose run --rm scanner \
  --target http://dvwa \
  --username admin \
  --password password \
  --format both \
  --output reports/scan \
  --report-base-url http://localhost:42001
```

`--report-base-url` rewrites internal Docker hostnames (`http://dvwa`) to browser-accessible URLs (`http://localhost:42001`) in the HTML report so every finding link is clickable.

Reports are written to `./reports/` on your host as `scan.html` and `scan.json`.

### Step 4 — Run with all tools (optional)

sqlmap and Nikto are already installed in the image:

```bash
docker compose run --rm scanner \
  --target http://dvwa \
  --username admin \
  --password password \
  --use-sqlmap --use-nikto \
  --screenshots \
  --format both \
  --output reports/scan \
  --report-base-url http://localhost:42001
```

Screenshots land in `./evidence/` on your host.

### Step 5 — Stop everything

```bash
docker compose down
```

To also wipe the database volume for a completely fresh start:

```bash
docker compose down -v
```

---

## Running against a standalone target (docker run)

To scan any target without Docker Compose, mount a reports directory and pass the target URL:

```bash
docker run --rm \
  -v $(pwd)/reports:/scanner/reports \
  wstg-scanner \
  --target http://TARGET \
  --output reports/scan \
  --format both
```

With authentication and all tools:

```bash
docker run --rm \
  -v $(pwd)/reports:/scanner/reports \
  -v $(pwd)/evidence:/scanner/evidence \
  wstg-scanner \
  --target http://TARGET \
  --username admin --password password \
  --use-sqlmap --use-nikto \
  --screenshots \
  --output reports/scan \
  --format both
```

---

## Juice Shop (optional test target)

```bash
docker compose --profile juice-shop up -d juice-shop

docker compose run --rm scanner \
  --target http://juice-shop:3000 \
  --format both \
  --output reports/scan
```

---

## Local Installation (alternative to Docker)

```bash
cd scanner
pip install -r requirements.txt
playwright install chromium
```

To install sqlmap and Nikto locally (Kali Linux / Debian):

```bash
sudo apt install sqlmap nikto
```

Run a scan:

```bash
python3 main.py --target http://localhost:42001 \
  --username admin --password password \
  --format both --output report
```

---

## CLI Reference

```bash
python3 main.py --target <URL> [options]
# or via Docker Compose:
docker compose run --rm scanner --target <URL> [options]
```

### Required

| Argument | Short | Description |
|---|---|---|
| `--target` | `-t` | Target base URL (e.g. `http://localhost:8080`) |

### Optional

| Argument | Short | Default | Description |
|---|---|---|---|
| `--auth-cookie` | | `None` | Session cookie (e.g. `PHPSESSID=abc123`) |
| `--browser-timeout` | | `15000` | Playwright navigation timeout (ms) |
| `--format` | | `html` | Report format: `json`, `html`, or `both` |
| `--headless` / `--no-headless` | | `True` | Run browser headlessly. Use `--no-headless` to see the browser window. |
| `--log-level` | | `info` | Verbosity: `debug`, `info`, `warning`, `error`, `critical` |
| `--max-depth` | | `2` | Maximum crawl depth from the start URL |
| `--open` | | `False` | Open the report in the default browser when done |
| `--output` | `-o` | `report` | Output base name (extension added automatically) |
| `--password` | | `None` | Login password (use with `--username`) |
| `--report-base-url` | | `None` | Public URL to substitute for `--target` in report links |
| `--screenshots` | | `False` | Save screenshots as evidence |
| `--use-nikto` | | `False` | Run Nikto after built-in checks |
| `--use-sqlmap` | | `False` | Run sqlmap after built-in checks |
| `--username` | | `None` | Login username (use with `--password`) |
| `--verbose` | `-v` | `False` | Force debug-level logging |

### Log levels

| Level | When to use |
|---|---|
| `debug` | Payloads, raw responses, every URL visited |
| `info` | General progress — pages crawled, findings recorded (default) |
| `warning` | Unexpected but recoverable — timeouts, out-of-scope redirects |
| `error` | A check or request failed; scan continues |
| `critical` | Fatal error; scanner cannot continue |

### Examples

```bash
# Basic scan
python3 main.py --target http://localhost:8080

# Authenticated scan with credentials
python3 main.py --target http://localhost:8080 --username admin --password password

# Authenticated scan with a session cookie
python3 main.py --target http://localhost:8080 --auth-cookie "PHPSESSID=abc123"

# Full scan: both report formats, screenshots, debug logging
python3 main.py --target http://localhost:8080 \
  --username admin --password password \
  --screenshots --format both --log-level debug --output results

# Full scan with external tools
python3 main.py --target http://localhost:8080 \
  --username admin --password password \
  --use-sqlmap --use-nikto --format both

# Open the HTML report automatically when done
python3 main.py --target http://localhost:8080 --format html --open
```

---

## Output

### HTML report

A self-contained styled HTML file (`<output>.html`). Includes a severity summary and a findings table with Severity, Type, URL, Detail, CWE (linked to MITRE), WSTG reference, CVE count, and Evidence columns.

### JSON report

A structured JSON file (`<output>.json`) for machine-readable output or import into other tooling:

```json
{
  "scanner": "OWASP WSTG Security Scanner",
  "target": "http://localhost:42001",
  "timestamp": "2026-05-03T10:00:00+00:00",
  "total_findings": 3,
  "severity_counts": { "High": 1, "Medium": 2, "Low": 0, "Info": 0 },
  "findings": [
    {
      "type": "SQL Injection (Error-Based)",
      "url": "http://localhost:42001/vulnerabilities/sqli/?id=1",
      "severity": "High",
      "detail": "Parameter 'id' triggered a database error response.",
      "evidence": "Payload: ' OR '1'='1 | Response snippet: ...SQL syntax error..."
    }
  ]
}
```

### Evidence directory

When `--screenshots` is enabled, `evidence/` is created automatically in the working directory (or at `/scanner/evidence` in the container). It contains full-page PNGs of crawled pages and any XSS alert dialogs.

---

## NVD CVE Enrichment

Every finding is automatically enriched with data from the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) — no flag needed.

| Field | Description |
|---|---|
| `cwe_id` | CWE identifier (e.g. `CWE-79`) |
| `cwe_name` | Human-readable CWE description |
| `wstg_ref` | OWASP WSTG reference (e.g. `WSTG-INPV-01`) |
| `owasp_top10` | OWASP Top 10 2021 category |
| `cve_count` | Total NVD CVEs linked to the CWE |
| `sample_cve` | Most recent relevant CVE ID |
| `nvd_url` | Link to NVD search results for the CWE |

The NVD API is queried once per unique CWE with a 6-second delay between requests to stay within the unauthenticated rate limit of 5 requests per 30 seconds.

---

## External Tool Integrations

Both tools degrade gracefully — if not installed, the scanner logs a warning and continues. In Docker, both are pre-installed.

### sqlmap (`--use-sqlmap`)

Runs [sqlmap](https://sqlmap.org/) against parameterised URLs and form actions after the built-in SQLi detector. Findings are tagged `SQL Injection (sqlmap confirmed)` with severity `High`.

### Nikto (`--use-nikto`)

Runs [Nikto](https://github.com/sullo/nikto) against the target root for server misconfigurations, outdated headers, dangerous paths, and default credentials. Severity is inferred from message keywords.

---

## OWASP WSTG Coverage

| Check | WSTG Reference | Module | Notes |
|---|---|---|---|
| Cross-Site Scripting | WSTG-INPV-01 | `detectors/xss.py` | HTTP reflection + browser-confirmed |
| SQL Injection | WSTG-INPV-05 | `detectors/sqli.py` | Error-based + boolean blind |
| HTTP Security Headers | WSTG-CONF-07 | `detectors/headers.py` | Per-origin, includes CSP quality check |
| Directory Listing | WSTG-CONF-04 | `detectors/dir_listing.py` | Common paths + crawled dirs |
| SQL Injection (confirmed) | WSTG-INPV-05 | `integrations/sqlmap_runner.py` | Optional (`--use-sqlmap`) |
| Server Misconfiguration | WSTG-CONF-* | `integrations/nikto_runner.py` | Optional (`--use-nikto`) |

---

## Cross-platform compatibility

The Docker setup works on macOS (Intel and Apple Silicon), Linux, and Windows. DVWA's database uses MariaDB 10.6, which provides native ARM64 images — MySQL 8.0 is incompatible with DVWA's SQL syntax, and MySQL 5.7 has no ARM64 image.

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests for crawling, payload injection, and NVD API |
| `beautifulsoup4` | HTML parsing and link extraction |
| `playwright` | Headless browser automation |
| `rich` | Formatted terminal output and progress bars |
| `urllib3` | Underlying HTTP transport |


---

## Quick Start (Docker — recommended)

Docker is the recommended way to run the scanner. It bundles Python, Chromium, sqlmap, and Nikto — nothing needs to be installed manually.

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (macOS, Windows, Linux)

### 1. Build the scanner image

Run this once from the repository root (the directory containing `Dockerfile`):

```bash
docker build -t wstg-scanner .
```

### 2. Start DVWA

[DVWA](https://github.com/digininja/dvwa) (Damn Vulnerable Web Application) is the recommended test target. The `docker-compose.yml` starts DVWA, its database, and an automated setup container that initialises the database and sets the security level to Low — no manual browser steps required.

```bash
docker compose up -d dvwa dvwa-setup
```

Wait ~30–60 seconds for setup to complete (you can follow progress with `docker compose logs -f dvwa-setup`), then verify DVWA is ready at http://localhost:42001.

### 3. Run the scanner

```bash
docker compose run --rm scanner \
  --target http://dvwa \
  --username admin \
  --password password \
  --format both \
  --output reports/scan
```

Reports are written to `./reports/` on your host machine as `scan.html` and `scan.json`.

### 4. Run with all tools (sqlmap + Nikto + screenshots)

```bash
docker compose run --rm scanner \
  --target http://dvwa \
  --username admin \
  --password password \
  --use-sqlmap --use-nikto \
  --screenshots \
  --format both \
  --output reports/scan
```

### 5. Stop everything

```bash
docker compose down
```

---

## Cross-platform compatibility

The Docker setup is tested on macOS (Intel and Apple Silicon), Linux, and Windows. DVWA's database is backed by MariaDB 10.6, which provides a native image for all three platforms (MySQL 8.0 is incompatible with DVWA's SQL syntax, and MySQL 5.7 has no ARM64 image).

---

## Local installation (alternative to Docker)

Requires Python 3.9+, pip, and optionally sqlmap / Nikto on PATH.

```bash
cd scanner
pip install -r requirements.txt
playwright install chromium
python3 main.py --target http://YOUR_TARGET --help
```

---

## Project structure

```
Dockerfile              # Scanner Docker image (Python + Chromium + sqlmap + Nikto)
docker-compose.yml      # DVWA + scanner + optional Juice Shop
scripts/
  setup-dvwa.sh         # Automated DVWA database init + security level setup
scanner/
  main.py               # Entry point — orchestrates the full scan pipeline
  cli.py                # Argument parsing
  config.py             # Central configuration
  http_crawler.py       # HTTP crawler (requests + BeautifulSoup)
  browser_crawler.py    # Playwright browser crawler
  payloads.py           # Injection payload library
  detectors/            # XSS, SQLi, headers, directory listing
  integrations/         # NVD CVE API, sqlmap, Nikto
  reporting/            # HTML, JSON, terminal summary reporters
  utils/                # Shared helpers (HTTP session, URL utils, logging)
  requirements.txt
  README.md             # Full usage and reference documentation
```
