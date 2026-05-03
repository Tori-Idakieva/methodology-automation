"""
config.py — Central configuration for the scanner.

All tunable constants (timeouts, headers, depth limits, etc.) live here
so they never need to be scattered across module files.
"""

from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    # Target
    target: str = "http://localhost"
    output: str = "report.json"

    # Crawl settings
    max_depth: int = 2
    max_urls: int = 100
    request_timeout: int = 10          # seconds

    # Browser settings
    headless: bool = True
    browser_timeout: int = 15000       # milliseconds (Playwright convention)

    # HTTP session headers
    default_headers: dict = field(default_factory=lambda: {
        "User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)",
    })

    # Payload limits (cap injections per URL to avoid flooding)
    max_payloads_per_param: int = 5
