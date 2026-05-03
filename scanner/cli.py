"""
cli.py — Command-line interface for the security scanner.

Parses user-supplied arguments (target URL, output path, scan options).
"""

import argparse


def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="OWASP WSTG-aligned web vulnerability scanner",
    )

    parser.add_argument(
        "--auth-cookie",
        default=None,
        help="Session cookie to include in requests (e.g. 'PHPSESSID=abc123'). Optional.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="html",
        help="Output report format: json, html, or both (default: html)",
    )
    parser.add_argument(
        "--browser-timeout",
        type=int,
        default=15000,
        help="Playwright navigation timeout in milliseconds (default: 15000)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=True,
        help="Run Playwright in headless mode (default: True)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum crawl depth from the starting URL (default: 2)",
    )
    parser.add_argument(
        "-o", "--output",
        default="report",
        help="Output file base name, without extension (default: report). Extension is added automatically based on --format.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password for login (used with --username to authenticate before scanning). Optional.",
    )
    parser.add_argument(
        "--screenshots",
        action="store_true",
        default=False,
        help="Capture browser screenshots as evidence for findings",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target base URL to scan (e.g. http://localhost:8080)",
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Username for login (used with --password to authenticate before scanning). Optional.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable debug-level logging output",
    )

    return parser.parse_args()
