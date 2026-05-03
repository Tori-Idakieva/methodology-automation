"""
detectors/headers.py — HTTP security header analyser.

OWASP WSTG reference: WSTG-CONF-07

Strategy:
  1. Fetch each URL with a HEAD (or GET) request.
  2. Check for the presence of recommended security headers.
  3. Flag missing or misconfigured headers as Medium/Low severity findings.
"""

from typing import List
from config import ScannerConfig
from payloads import EXPECTED_SECURITY_HEADERS
from utils.logger import get_logger

logger = get_logger(__name__)


class HeadersDetector:
    """Detect missing or weak HTTP security response headers."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def run(self, urls: List[str]) -> List[dict]:
        """
        Analyse security headers for all supplied URLs.

        Returns a list of finding dicts.
        """
        findings = []
        for url in urls:
            findings.extend(self._test_url(url))
        return findings

    def _test_url(self, url: str) -> List[dict]:
        """
        Fetch response headers and compare against EXPECTED_SECURITY_HEADERS.
        """
        # TODO:
        #   - requests.head(url) or requests.get(url, stream=True)
        #   - for each header in EXPECTED_SECURITY_HEADERS:
        #       if header not in response.headers → append finding
        raise NotImplementedError

    def _evaluate_csp(self, csp_value: str) -> List[str]:
        """
        Parse a Content-Security-Policy header value and flag weak directives.

        Returns a list of warning strings (empty if policy looks adequate).
        """
        # TODO: check for 'unsafe-inline', 'unsafe-eval', wildcard sources
        raise NotImplementedError
