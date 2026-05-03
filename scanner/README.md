# OWASP WSTG Security Scanner

A Python-based web vulnerability scanner that combines traditional HTTP-level testing with Playwright-powered browser automation. The scanner is aligned with the [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) and is designed as a proof-of-concept covering a meaningful subset of the methodology.

---

## Overview

The scanner operates in three stages:

1. **Crawl** — Discovers URLs on the target using both HTTP requests and a headless browser, capturing content that requires JavaScript execution or client-side rendering.
2. **Detect** — Runs vulnerability checks across discovered URLs, injecting payloads and analysing responses for signs of weakness.
3. **Report** — Writes an HTML report (default) and/or a JSON report, and prints a colour-coded terminal summary.

---

## How It Works

### Two-crawler approach

The scanner runs two crawlers in parallel and merges their results before detection begins.

The **HTTP crawler** (`http_crawler.py`) uses `requests` and `BeautifulSoup` to fetch pages and extract links without executing JavaScript. It is fast and lightweight, and handles redirect scope checks, auth cookie injection, and form discovery from raw HTML.

The **browser crawler** (`browser_crawler.py`) uses Playwright to navigate pages in a real headless Chromium browser. It executes JavaScript, handles client-side routing, and can interact with dynamic content. It also handles login form submission if credentials are provided, captures screenshots as evidence, and listens for browser dialog events (`alert`, `confirm`, `prompt`) which are used as XSS confirmation signals.

Both crawlers produce a list of discovered URLs and a list of form injection vectors (action URL, method, input field names) that the detectors consume directly.

### Authentication

The scanner supports two authentication methods:

- **Credentials** (`--username` / `--password`) — the browser crawler navigates to the target, detects the login form, fills in the credentials and submits before crawling begins. Generic enough to work with DVWA and Juice Shop without hardcoding field names.
- **Session cookie** (`--auth-cookie`) — injects a pre-existing session cookie into both the HTTP session and the browser context, bypassing the login step entirely.

### Evidence

When `--screenshots` is enabled, the browser crawler saves a full-page screenshot of every crawled page and any triggered alert dialogs to an `evidence/` directory created automatically in the working directory.

---

## Project Structure

```
scanner/
├── main.py               # Entry point — orchestrates crawl → detect → report
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
├── reporting/
│   ├── __init__.py
│   ├── html_report.py    # Writes findings to a styled HTML file
│   ├── json_report.py    # Writes findings to a JSON file
│   └── summary.py        # Prints a colour-coded terminal summary
├── utils/
│   ├── __init__.py
│   ├── logger.py         # Centralised logging (get_logger, configure_from_config)
│   └── file_handler.py   # File I/O helpers and screenshot path management
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.9 or higher
- pip

---

## Installation

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Playwright and Chromium

```bash
pip install playwright
playwright install chromium
```

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
| `--headless` | | `True` | Run Playwright in headless mode |
| `--help` | `-h` | | Print all available options and exit |
| `--log-level` | | `info` | Logging verbosity: `debug`, `info`, `warning`, `error`, `critical`. Overridden by `--verbose` |
| `--max-depth` | | `2` | Maximum crawl depth from the starting URL |
| `--output` | `-o` | `report` | Base name for the output file, without extension (extension added automatically) |
| `--password` | | `None` | Password for login — use with `--username` |
| `--screenshots` | | `False` | Capture browser screenshots as evidence for findings |
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

---

## OWASP WSTG Coverage

| Check | WSTG Reference | Module | Status |
|---|---|---|---|
| Cross-Site Scripting (XSS) | WSTG-INPV-01 | `detectors/xss.py` | In progress |
| SQL Injection | WSTG-INPV-05 | `detectors/sqli.py` | In progress |
| HTTP Security Headers | WSTG-CONF-07 | `detectors/headers.py` | In progress |
| Directory Listing | WSTG-CONF-04 | `detectors/dir_listing.py` | In progress |

---

## Test Targets

The scanner is designed to be tested locally against intentionally vulnerable applications:

- **DVWA** (Damn Vulnerable Web Application) — `https://github.com/digininja/DVWA`
- **OWASP Juice Shop** — `https://github.com/juice-shop/juice-shop`

Both can be run locally via Docker. See their respective repositories for setup instructions.

---

## Output

### HTML report (default)

A self-contained styled HTML file written to `<output>.html`. Includes a severity summary and a findings table with colour-coded badges — easier to read and share than raw JSON.

### JSON report

A structured report written to `<output>.json`. Useful for machine-readable output or importing into other tooling:

```json
{
  "scanner": "OWASP WSTG Security Scanner",
  "target": "http://localhost:8080",
  "timestamp": "2026-05-03T10:00:00+00:00",
  "total_findings": 3,
  "findings": [
    {
      "type": "XSS",
      "url": "http://localhost:8080/search?q=...",
      "severity": "High",
      "detail": "Payload reflected and executed in browser DOM",
      "evidence": "evidence/xss_search.png"
    }
  ]
}
```

### Terminal summary

A colour-coded table is printed to stdout at the end of the scan showing all findings grouped by severity.

### Evidence directory

When `--screenshots` is enabled, a folder named `evidence/` is created automatically in the working directory. It contains full-page PNG screenshots of crawled pages and any triggered alert dialogs, named by page index or vulnerability label.

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests for crawling and payload injection |
| `beautifulsoup4` | HTML parsing and link extraction |
| `playwright` | Headless browser automation and DOM interaction |
| `rich` | Formatted terminal output for the summary report |
