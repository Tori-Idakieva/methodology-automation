"""
config.py — Central configuration for the scanner.

All tunable constants (timeouts, headers, depth limits, etc.) live here
so they never need to be scattered across module files.
"""

import argparse
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScannerConfig:
    # Target & output
    target: str = "http://localhost"
    output: str = "report"              # base name, no extension
    format: str = "html"
    # When the scanner reaches the target via an internal network address
    # (e.g. Docker service name "http://dvwa") but the user's browser uses a
    # different URL (e.g. "http://localhost:42001"), set report_base_url to the
    # browser-accessible address. All finding URLs in the report are rewritten
    # from target → report_base_url before the report is written.
    # When None (the default), report URLs are left as-is (equal to target).
    # Set this when --target is a Docker-internal hostname that differs from
    # what a browser can reach, e.g. report_base_url="http://localhost:42001"
    # while target="http://dvwa".
    report_base_url: Optional[str] = None

    # Credentials / auth — all optional, None when not supplied
    auth_cookie: Optional[str] = None
    username:    Optional[str] = None
    password:    Optional[str] = None

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

    # External tool integrations (optional, require tools to be installed)
    use_sqlmap: bool = False
    use_nikto:  bool = False

    # Post-scan behaviour
    open_report: bool = False   # open report(s) in default viewer after writing

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
            use_sqlmap=args.use_sqlmap,
            use_nikto=args.use_nikto,
            open_report=args.open,
            report_base_url=getattr(args, "report_base_url", None),
        )
