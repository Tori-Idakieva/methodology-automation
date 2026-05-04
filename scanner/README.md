# OWASP WSTG Security Scanner

A Python-based web vulnerability scanner that combines traditional HTTP-level testing with Playwright-powered browser automation. The scanner is aligned with the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) and is designed as a proof-of-concept covering a meaningful subset of the methodology.

---

## Overview

The scanner operates in five stages:

1. **Crawl** — Discovers URLs on the target using both HTTP requests and a headless browser, capturing content that requires JavaScript execution or client-side rendering.
2. **Detect** — Runs built-in vulnerability checks across discovered URLs, injecting payloads and analysing responses for signs of weakness.
3. **Integrate** — Optionally invokes external tools (sqlmap, Nikto) for deeper, specialised testing of the same targets.
4. **Enrich** — Queries the NVD CVE API 2.0 to annotate each finding with its CWE ID, OWASP WSTG reference, related CVE count, and average CVSS score.
5. **Report** — Writes an HTML report (default) and/or a JSON report, and prints a colour-coded terminal summary.

---

## How It Works

### Two-crawler approach

The scanner runs two crawlers and merges their results before detection begins.

The **HTTP crawler** (`http_crawler.py`) uses `requests` and `BeautifulSoup` to fetch pages and extract links without executing JavaScript. It is fast and lightweight, and handles redirect scope checks, auth cookie injection, and form discovery from raw HTML.

The **browser crawler** (`browser_crawler.py`) uses Playwright to navigate pages in a real headless Chromium browser. It executes JavaScript, handles client-side routing, and can interact with dynamic content. It also handles login form submission if credentials are provided, captures screenshots as evidence, and listens for browser dialog events (`alert`, `confirm`, `prompt`) which are used as XSS confirmation signals.

Both crawlers produce a list of discovered URLs and a list of form injection vectors (action URL, method, input field names) that the detectors consume directly.

### Authentication

The scanner supports two authentication methods:

- **Credentials** (`--username` / `--password`) — the browser crawler navigates to the target, detects the login form, fills in the credentials and submits before crawling begins. Field detection is generic and does not hardcode field names.
- **Session cookie** (`--auth-cookie`) — injects a pre-existing session cookie into both the HTTP session and the browser context, bypassing the login step entirely.

### Evidence

When `--screenshots` is enabled, the browser crawler saves a full-page screenshot of every crawled page and any triggered alert dialogs to an `evidence/` directory created automatically in the working directory.

---

## Project Structure

```
scanner/
├── main.py               # Entry point — orchestrates crawl → detect → integrate → enrich → report
├── cli.py                # Argument parsing
├── config.py             # Central configuration (timeouts, limits, defaults)
├── http_crawler.py       # HTTP-level crawler (requests + BeautifulSoup)
├── browser_crawler.py    # Playwright browser crawler
├── payloads.py           # Payload and signature library for all detectors
├── detectors/
│   ├── __init__.py       # Shared finding dict schema
│   ├── xss.py            # Cross-Site Scripting detector (WSTG-INPV-01)
│   ├── sqli.py           # SQL Injection detector (WSTG-INPV-05)
│   ├── headers.py        # Security header analyser (WSTG-CONF-07)
│   └── dir_listing.py    # Directory listing detector (WSTG-CONF-04)
├── integrations/
│   ├── __init__.py
│   ├── nvd_api.py        # NVD CVE API 2.0 enrichment (CWE, CVSS, CVE count)
│   ├── sqlmap_runner.py  # sqlmap subprocess wrapper (optional, --use-sqlmap)
│   └── nikto_runner.py   # Nikto subprocess wrapper (optional, --use-nikto)
├── reporting/
│   ├── __init__.py
│   ├── html_report.py    # Writes findings to a styled HTML file
│   ├── json_report.py    # Writes findings to a JSON file
│   └── summary.py        # Prints a colour-coded terminal summary
├── utils/
│   ├── __init__.py
│   ├── console.py        # Shared Rich Console instance
│   ├── logger.py         # Centralised logging (get_logger, configure_from_config)
│   ├── http.py           # Shared requests.Session factory
│   ├── url.py            # URL utility functions (normalise, scope check, inject)
│   └── file_handler.py   # File I/O helpers and screenshot path management
├── requirements.txt
└── README.md
```

---

## Requirements

### Docker (recommended)

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Mac/Windows) or [Docker Engine](https://docs.docker.com/engine/install/) (Linux)

Docker includes both the `docker` CLI and Docker Compose. No other dependencies are needed — Python, Chromium, sqlmap, and Nikto are all bundled in the image.

### Local installation

- Python 3.9 or higher
- pip

---

## Running with Docker Compose (recommended)

Docker Compose is the recommended way to run the scanner. The image includes Python, Chromium, **sqlmap**, and **Nikto** — nothing needs to be installed manually. All commands run from the **project root** (the directory containing `docker-compose.yml`).

### Build the image

Run once (or after changing `requirements.txt` or `Dockerfile`):

```bash
docker compose build scanner
```

Code changes in `scanner/` are picked up immediately without rebuilding — the compose file uses a live bind mount.

### Basic scan

```bash
docker compose run --rm scanner \
  --target http://TARGET \
  --format both
```

Reports land in `./reports/` on your host with a timestamped filename (e.g. `scan-20260506-153042.html`). Pass `--output <name>` to choose a specific name.

### Authenticated scan

```bash
docker compose run --rm scanner \
  --target http://TARGET \
  --username admin --password password \
  --format both
```

### Full scan with sqlmap, Nikto, and screenshots

```bash
docker compose run --rm scanner \
  --target http://TARGET \
  --username admin --password password \
  --use-sqlmap --use-nikto \
  --screenshots \
  --format both
```

Screenshots land in `./evidence/` on your host.

### Show help

```bash
docker compose run --rm scanner --help
```

---

## Scan DVWA with Docker Compose

The `docker-compose.yml` spins up both the scanner and DVWA together on a shared internal network. The scanner reaches DVWA by its service hostname (`http://dvwa`) without any port exposure needed.

### Before you start

Build the scanner image once to install system packages and Python dependencies:

```bash
docker compose build scanner
```

**You do not need to rebuild after editing scanner code.** The `docker-compose.yml` mounts the `scanner/` directory as a live bind mount, so any code changes are picked up immediately the next time you run the scanner. Only rebuild if you add a package to `requirements.txt` or change the `Dockerfile`.

The DVWA and MariaDB images are pulled automatically by Docker Compose on first run — no manual `docker pull` needed.

### Quick start

The `dvwa-setup` service creates the DVWA database and sets the security level to Low automatically. If setup is unavailable or fails, the scanner detects the uninitialised state and initialises the database itself before scanning.

```bash
# 1. Start DVWA, its database, and the one-shot setup service.
#    Docker pulls the required images automatically on first run.
docker compose up -d dvwa dvwa-setup

# 2. Wait ~30-60 seconds for setup to complete. Follow progress with:
docker compose logs -f dvwa-setup
#    Look for: [setup-dvwa] Setup complete. DVWA is ready to scan.

# 3. Run the scanner. Use --report-base-url so links in the HTML report
#    point to the browser-accessible URL rather than the internal hostname.
docker compose run --rm scanner \
  --target http://dvwa \
  --username admin \
  --password password \
  --format both \
  --report-base-url http://localhost:42001
```

Default DVWA credentials: **username = admin**, **password = password**

Reports are written to `./reports/` on your host machine.

### With external tools

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

### Full reset

If DVWA becomes unresponsive or login stops working, tear everything down including the database volume and start fresh:

```bash
docker compose down -v
docker compose up -d dvwa dvwa-setup
docker compose logs -f dvwa-setup
```

### Stop everything

```bash
docker compose down
```

---

## Local Installation

Local installation is an alternative to Docker. All commands should be run from the **`scanner/` directory**.

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

> **Kali Linux:** add `--break-system-packages` if pip refuses to install outside a virtual environment.

### Step 2 — Install Playwright and Chromium

```bash
playwright install chromium
playwright install-deps chromium    # Linux only — installs OS-level browser deps
```

### Step 3 — Install external tools (optional)

| Platform | sqlmap | Nikto |
|---|---|---|
| **Kali Linux** | Pre-installed (or `sudo apt install sqlmap`) | Pre-installed (or `sudo apt install nikto`) |
| **Ubuntu / Debian** | `sudo apt install sqlmap` | `sudo apt install nikto` |
| **macOS** | `brew install sqlmap` | `brew install nikto` |
| **Windows** | `pip install sqlmap` | Requires Perl — use WSL2 instead (see below) |

### Platform notes

**macOS:** Works natively on Intel and Apple Silicon. Install Homebrew (`brew.sh`) for the simplest path to sqlmap and Nikto.

**Linux (Ubuntu / Debian):** Run `playwright install-deps chromium` to install the shared libraries (`libgtk`, `libnss`, etc.) required by Playwright's bundled Chromium.

**Kali Linux:** sqlmap and Nikto are typically pre-installed. Run `playwright install chromium && playwright install-deps chromium` to add the browser.

**Windows:** The scanner runs natively but Nikto requires Perl and is difficult to set up without a package manager. **WSL2 is strongly recommended** — install Ubuntu via WSL2, then follow the Linux instructions above. Docker Desktop with WSL2 integration is the simplest path on Windows.

---

## Usage

```bash
python3 main.py --target <URL> [options]
```

To print all available options at any time:

```bash
python3 main.py --help
```

### Required argument

| Argument | Short | Description |
|---|---|---|
| `--target` | `-t` | Target base URL to scan (e.g. `http://localhost:8080`) |

### Optional arguments

| Argument | Short | Default | Description |
|---|---|---|---|
| `--auth-cookie` | | `None` | Session cookie to attach to requests (e.g. `PHPSESSID=abc123`) |
| `--browser-timeout` | | `15000` | Playwright navigation timeout in milliseconds |
| `--format` | | `html` | Report output format: `json`, `html`, or `both` |
| `--headless` / `--no-headless` | | `True` | Run Playwright in headless mode (default). Pass `--no-headless` to show the browser window. |
| `--help` | `-h` | | Print all available options and exit |
| `--log-level` | | `info` | Logging verbosity: `debug`, `info`, `warning`, `error`, `critical`. Overridden by `--verbose` |
| `--max-depth` | | `2` | Maximum crawl depth from the starting URL |
| `--open` | | `False` | Open the report(s) in the default browser when the scan completes |
| `--output` | `-o` | `scan-YYYYMMDD-HHMMSS` | Base name for the output file. A timestamp is always appended (e.g. `--output myscan` → `myscan-20260506-153042.html`). Defaults to `scan-YYYYMMDD-HHMMSS` when omitted. Successive scans never overwrite each other. |
| `--password` | | `None` | Password for login — use with `--username` |
| `--report-base-url` | | `None` | Public-facing base URL to substitute into report links. Use when the scanner reaches the target via an internal hostname (e.g. `http://dvwa`) but report links should be browser-accessible (e.g. `http://localhost:42001`) |
| `--screenshots` | | `False` | Capture browser screenshots as evidence for findings |
| `--use-nikto` | | `False` | Run Nikto against the target after built-in checks (requires Nikto on PATH) |
| `--use-sqlmap` | | `False` | Run sqlmap against injectable URLs after built-in checks (requires sqlmap on PATH) |
| `--username` | | `None` | Username for login — use with `--password` |
| `--verbose` | `-v` | `False` | Force debug-level logging, overrides `--log-level` |

### Log levels

| Level | When to use |
|---|---|
| `debug` | Fine-grained detail — payloads injected, raw responses, every URL visited |
| `info` | General progress — pages crawled, findings recorded (default) |
| `warning` | Unexpected but recoverable — timeouts, redirects out of scope |
| `error` | A check or request failed, scan continues |
| `critical` | Fatal error, scanner cannot continue |

### Examples

**Basic scan:**
```bash
python3 main.py --target http://localhost:8080
```

**Authenticated scan using credentials:**
```bash
python3 main.py --target http://localhost:8080 --username admin --password password
```

**Authenticated scan using an existing session cookie:**
```bash
python3 main.py --target http://localhost:8080 --auth-cookie "PHPSESSID=abc123"
```

**Scan with JSON output and warning-level logging:**
```bash
python3 main.py --target http://localhost:8080 --format json --log-level warning
```

**Full scan with screenshots, both report formats, and debug logging:**
```bash
python3 main.py --target http://localhost:8080 \
  --username admin --password password \
  --screenshots --format both \
  --log-level debug --output results
```

**Scan with external tools (sqlmap + Nikto):**
```bash
python3 main.py --target http://localhost:8080 \
  --username admin --password password \
  --use-sqlmap --use-nikto --format both
```

**Open the report automatically when done:**
```bash
python3 main.py --target http://localhost:8080 --format html --open
```

---

## External Tool Integrations

Two optional integrations can be enabled at runtime. Both tools degrade gracefully — if they are not installed, the scanner logs a warning and continues without them.

When running via **Docker**, sqlmap and Nikto are already installed in the image. No separate installation is needed — just add `--use-sqlmap` or `--use-nikto` to your `docker compose run` command.

### sqlmap (`--use-sqlmap`)

Runs [sqlmap](https://sqlmap.org/) against any URLs with query parameters and against discovered form actions after the built-in SQLi detector has finished. sqlmap uses a broader injection technique library than the built-in detector and can confirm injections with higher certainty.

Findings from sqlmap are tagged `SQL Injection (sqlmap confirmed)` with severity `High` and `source: sqlmap`.

**Installation (local / Kali Linux only — not needed with Docker):**
```bash
sudo apt install sqlmap
```

### Nikto (`--use-nikto`)

Runs [Nikto](https://github.com/sullo/nikto) against the root target for web server misconfiguration, outdated software headers, dangerous file paths, and default credentials. Nikto covers checks orthogonal to the built-in detectors.

Severity is inferred from the Nikto message text using keyword matching (e.g. "sql injection" → High, "directory listing" → Medium, "header" → Low). Findings are tagged `Nikto Finding` and `source: nikto`.

**Installation (local / Kali Linux only — not needed with Docker):**
```bash
sudo apt install nikto
```

---

## NVD CVE Enrichment

Every finding is automatically enriched with data from the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) after detection completes — no flag required.

Enrichment adds the following fields to each finding:

| Field | Description |
|---|---|
| `cwe_id` | Common Weakness Enumeration identifier (e.g. `CWE-79`) |
| `cwe_name` | Human-readable CWE description |
| `wstg_ref` | OWASP WSTG test case reference (e.g. `WSTG-INPV-01`) |
| `owasp_top10` | Mapped OWASP Top 10 2021 category |
| `cve_count` | Total CVEs in NVD linked to this CWE |
| `cvss_avg` | Average CVSS base score of the most recent CVEs |
| `sample_cve` | ID of the most recent relevant CVE |
| `nvd_url` | Link to NVD search results for the CWE |

The HTML report renders CWE and CVE count as clickable links to MITRE and NVD respectively. The NVD API is queried once per unique CWE with a 6-second delay between requests to respect the unauthenticated rate limit of 5 requests per 30 seconds.

---

## OWASP WSTG Coverage

| Check | WSTG Reference | Module | Status |
|---|---|---|---|
| Cross-Site Scripting (XSS) | WSTG-INPV-01 | `detectors/xss.py` | Complete |
| SQL Injection | WSTG-INPV-05 | `detectors/sqli.py` | Complete |
| HTTP Security Headers | WSTG-CONF-07 | `detectors/headers.py` | Complete |
| Directory Listing | WSTG-CONF-04 | `detectors/dir_listing.py` | Complete |
| SQL Injection (confirmed) | WSTG-INPV-05 | `integrations/sqlmap_runner.py` | Optional (`--use-sqlmap`) |
| Web Server Misconfiguration | WSTG-CONF-* | `integrations/nikto_runner.py` | Optional (`--use-nikto`) |

---

## Test Targets

The scanner is designed to be tested locally against intentionally vulnerable applications. The recommended target is:

- **DVWA** (Damn Vulnerable Web Application) — `https://github.com/digininja/DVWA`

The easiest way to run it is via Docker Compose — see the [Scan DVWA with Docker Compose](#scan-dvwa-with-docker-compose) section above.

Alternatively, to run DVWA standalone:

```bash
docker pull ghcr.io/digininja/dvwa
docker run -d -p 42001:80 ghcr.io/digininja/dvwa
```

Navigate to `http://localhost:42001`, log in with the default credentials (`admin` / `password`), complete the setup, then scan:

```bash
# Local
python3 main.py --target http://localhost:42001 \
  --username admin --password password \
  --format both --screenshots

# Docker Compose
docker compose run --rm scanner \
  --target http://localhost:42001 \
  --username admin --password password \
  --use-sqlmap --use-nikto \
  --format both
```

> **Note:** When running DVWA via Docker Compose, the scanner reaches it as `http://dvwa` (internal hostname). When running DVWA standalone on your host, use `http://localhost:42001` — but replace `localhost` with `host.docker.internal` if you are running the scanner itself inside Docker.

---

## Output

### HTML report (default)

A self-contained styled HTML file written to `<output>.html`. Includes a severity summary card row and a findings table with colour-coded severity badges. Each row includes Severity, Type, URL, Detail, CWE (linked to MITRE), WSTG reference, CVE count (linked to NVD), and Evidence columns.

### JSON report

A structured report written to `<output>.json`. Useful for machine-readable output or importing into other tooling:

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

### Terminal summary

A colour-coded table is printed to stdout at the end of the scan showing all findings grouped by severity.

### Evidence directory

When `--screenshots` is enabled, a folder named `evidence/` is created automatically in the working directory. It contains full-page PNG screenshots of crawled pages and any triggered alert dialogs, named by page index or vulnerability label. When running via Docker, mount `/scanner/evidence` to a host path to retrieve screenshots after the scan.

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests for crawling, payload injection, and NVD API calls |
| `beautifulsoup4` | HTML parsing and link extraction |
| `playwright` | Headless browser automation and DOM interaction |
| `rich` | Formatted terminal output for the summary report |

External tools (already included in the Docker image — manual installation only needed for local runs):

| Tool | Local Installation | Flag |
|---|---|---|
| `sqlmap` | `sudo apt install sqlmap` (Kali) | `--use-sqlmap` |
| `nikto` | `sudo apt install nikto` (Kali) | `--use-nikto` |
