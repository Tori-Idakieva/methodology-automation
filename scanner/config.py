"""
config.py — Central configuration for the scanner.

All tunable constants (timeouts, headers, depth limits, etc.) live here
so they never need to be scattered across module files.
"""

import argparse
from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    # Target & output
    target: str = "http://localhost"
    output: str = "report"              # base name, no extension
    format: str = "html"

    # Credentials / auth
    auth_cookie: str = None
    username: str = None
    password: str = None

    # Crawl settings
    max_depth: int = 2
    max_urls: int = 100
    request_timeout: int = 10           # seconds

    # Browser settings
    headless: bool = True
    browser_timeout: int = 15000        # milliseconds (Playwright convention)
    screenshots: bool = False

    # Logging
    log_level: str = "info"
    verbose: bool = False

    # HTTP session headers
    default_headers: dict = field(default_factory=lambda: {
        "User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)",
    })

    # Payload limits (cap injections per URL to avoid flooding)
    max_payloads_per_param: int = 5

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "ScannerConfig":
        """Build a ScannerConfig from parsed CLI arguments."""
        return cls(
            target=args.target,
            output=args.output,
            format=args.format,
            auth_cookie=args.auth_cookie,
            username=args.username,
            password=args.password,
            max_depth=args.max_depth,
            headless=args.headless,
            browser_timeout=args.browser_timeout,
            screenshots=args.screenshots,
            log_level=args.log_level,
            verbose=args.verbose,
        )
