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
docker-compose.yml      # DVWA + scanner orchestration
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
  --report-base-url http://localhost:42001
```

`--report-base-url` rewrites internal Docker hostnames (`http://dvwa`) to browser-accessible URLs (`http://localhost:42001`) in the HTML report so every finding link is clickable. Reports are written to `./reports/` on your host with an auto-generated timestamped filename (e.g. `scan-20260506-153042.html`).

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

## Scanning a different target

To scan any target, just change `--target` and remove the `--report-base-url` flag (that is only needed when the scanner reaches the target via an internal Docker hostname):

```bash
docker compose run --rm scanner \
  --target http://YOUR_TARGET \
  --username admin --password password \
  --use-sqlmap --use-nikto \
  --screenshots \
  --format both
```

Reports are written to `./reports/` on your host. A timestamp is always appended to the filename — if you pass `--output myscan` the file is `myscan-20260506-153042.html`; with no `--output` it defaults to `scan-20260506-153042.html`. Successive scans never overwrite each other.

---

## Local Installation (alternative to Docker)

All commands below are run from the `scanner/` directory. Docker is recommended for Windows and macOS — local install is simplest on Linux and Kali.

### Step 1 — Install Python dependencies

```bash
cd scanner
pip install -r requirements.txt      # Linux / macOS / Windows
```

> **Kali Linux note:** If pip refuses to install outside a virtual environment, add `--break-system-packages`:
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

### Step 2 — Install Playwright and Chromium

```bash
playwright install chromium
playwright install-deps chromium     # Linux only — installs OS-level browser deps
```

On Windows you can skip `install-deps`; Playwright manages its own browser binaries.

### Step 3 — Install external tools (optional)

| Platform | sqlmap | Nikto |
|---|---|---|
| **Kali Linux** | Pre-installed (or `sudo apt install sqlmap`) | Pre-installed (or `sudo apt install nikto`) |
| **Ubuntu / Debian** | `sudo apt install sqlmap` | `sudo apt install nikto` |
| **macOS** | `brew install sqlmap` | `brew install nikto` |
| **Windows** | `pip install sqlmap` | Manual — download from [github.com/sullo/nikto](https://github.com/sullo/nikto), requires Perl. Recommended to use WSL2 instead. |

### Step 4 — Run a scan

```bash
python3 main.py --target http://localhost:42001 \
  --username admin --password password \
  --format both
```

On Windows (native, not WSL):
```
python main.py --target http://localhost:42001 --username admin --password password
```

### Platform notes

**macOS (Intel and Apple Silicon):** Works natively. Playwright's bundled Chromium supports both architectures. Install Homebrew (`brew.sh`) for the easiest path to sqlmap and Nikto.

**Linux (Ubuntu / Debian):** Run `playwright install-deps chromium` after the Playwright install — this installs `libgtk`, `libnss`, and other shared libraries that the bundled Chromium binary needs.

**Kali Linux:** sqlmap and Nikto are typically pre-installed. Run `playwright install chromium && playwright install-deps chromium` to add Playwright's Chromium. Kali uses a newer Python packaging policy, so add `--break-system-packages` to pip if prompted.

**Windows:** The scanner runs on Windows natively but sqlmap and Nikto are harder to install without package manager support. **WSL2 (Windows Subsystem for Linux) is strongly recommended** — follow the Linux instructions above inside a WSL2 Ubuntu terminal, then run DVWA via Docker Desktop with WSL2 integration enabled.

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
| `--output` | `-o` | `scan-YYYYMMDD-HHMMSS` | Base name for the output file. A timestamp is always appended (e.g. `--output myscan` → `myscan-20260506-153042.html`). Defaults to `scan-YYYYMMDD-HHMMSS` when omitted. |
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

## Cross-platform notes

The Docker setup targets macOS, Linux, and Windows. DVWA's database uses MariaDB 10.6 — MySQL 8.0 is incompatible with DVWA's SQL syntax, and MySQL 5.7 has no ARM64 image, so MariaDB 10.6 is required for Apple Silicon support.

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests for crawling, payload injection, and NVD API |
| `beautifulsoup4` | HTML parsing and link extraction |
| `playwright` | Headless browser automation |
| `rich` | Formatted terminal output and progress bars |
| `urllib3` | Underlying HTTP transport |
