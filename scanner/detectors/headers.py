"""
detectors/headers.py — HTTP security header analyser.

OWASP WSTG reference: WSTG-CONF-07

Strategy:
  1. Fetch each URL with a HEAD request (falls back to GET if HEAD fails).
  2. Check for the presence of recommended security headers.
  3. Evaluate Content-Security-Policy quality if present.
  4. Flag missing or misconfigured headers as Medium/Low severity findings.
"""

import requests
from typing import List, Optional
from config import ScannerConfig
from payloads import EXPECTED_SECURITY_HEADERS
from utils.logger import get_logger
from utils.http import build_session
from utils.url import origin

logger = get_logger(__name__)

# Headers considered misconfigured if set to these known weak values
WEAK_HEADER_VALUES = {
    "X-Frame-Options":        ["ALLOWALL"],
    "X-Content-Type-Options": [],           # any value other than "nosniff" is weak
    "Referrer-Policy":        ["unsafe-url"],
}

# CSP directives that weaken the policy significantly
WEAK_CSP_DIRECTIVES = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]


class HeadersDetector:
    """Detect missing or weak HTTP security response headers."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = build_session(config)

    def run(self, urls: List[str]) -> List[dict]:
        """
        Analyse security headers for all supplied URLs.

        Only tests each unique origin once — headers are a server-level
        concern and won't differ between pages on the same host.

        Returns a list of finding dicts.
        """
        findings = []
        seen_origins = set()

        for url in urls:
            url_origin = origin(url)
            if url_origin in seen_origins:
                continue
            seen_origins.add(url_origin)
            findings.extend(self._test_url(url))

        return findings

    def _test_url(self, url: str) -> List[dict]:
        """
        Fetch response headers and check against EXPECTED_SECURITY_HEADERS.
        Also evaluates CSP quality if the header is present.
        """
        response = self._fetch(url)
        if response is None:
            return []

        findings = []
        headers = response.headers

        logger.info(f"Checking security headers on: {url}")

        for header in EXPECTED_SECURITY_HEADERS:
            if header not in headers:
                logger.warning(f"Missing header [{header}] on {url}")
                findings.append({
                    "type":     "Missing Security Header",
                    "url":      url,
                    "severity": "Medium",
                    "detail":   f"Header '{header}' is not set.",
                    "evidence": f"Response did not include '{header}'",
                })
            else:
                value = headers[header]
                logger.debug(f"Found header [{header}]: {value}")

                # Check for known weak values
                weak = self._check_weak_value(header, value)
                if weak:
                    findings.append({
                        "type":     "Weak Security Header",
                        "url":      url,
                        "severity": "Low",
                        "detail":   f"Header '{header}' is set to a weak value: {value}",
                        "evidence": f"{header}: {value}",
                    })

        # Evaluate CSP quality if present
        csp_value = headers.get("Content-Security-Policy")
        if csp_value:
            csp_warnings = self._evaluate_csp(csp_value)
            for warning in csp_warnings:
                findings.append({
                    "type":     "Weak Content-Security-Policy",
                    "url":      url,
                    "severity": "Low",
                    "detail":   warning,
                    "evidence": f"Content-Security-Policy: {csp_value}",
                })

        return findings

    def _fetch(self, url: str) -> Optional[requests.Response]:
        """
        Attempt a HEAD request, fall back to GET if HEAD is not supported.

        Returns the response or None on failure.
        """
        for method in ("HEAD", "GET"):
            try:
                response = self.session.request(
                    method,
                    url,
                    timeout=self.config.request_timeout,
                    allow_redirects=True,
                    stream=(method == "GET"),  # don't download body on GET
                )
                logger.debug(f"HTTP {method} {response.status_code} — {url}")
                return response
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on {method} {url}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error on {method} {url}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed ({method} {url}): {e}")

        return None

    def _evaluate_csp(self, csp_value: str) -> List[str]:
        """
        Parse a Content-Security-Policy header and flag weak directives.

        Returns a list of warning strings, empty if the policy looks adequate.
        """
        warnings = []

        for directive in WEAK_CSP_DIRECTIVES:
            if directive in csp_value:
                warnings.append(
                    f"Content-Security-Policy contains weak directive: {directive}"
                )

        # Flag if no default-src or script-src is defined at all
        if "default-src" not in csp_value and "script-src" not in csp_value:
            warnings.append(
                "Content-Security-Policy has no 'default-src' or 'script-src' directive"
            )

        return warnings

    def _check_weak_value(self, header: str, value: str) -> bool:
        """
        Return True if the header's value is known to be weak.
        """
        if header == "X-Content-Type-Options":
            return value.strip().lower() != "nosniff"

        weak_values = WEAK_HEADER_VALUES.get(header, [])
        return value.strip().upper() in [w.upper() for w in weak_values]

