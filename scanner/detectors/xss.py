"""
detectors/xss.py — Cross-Site Scripting (XSS) detector.

OWASP WSTG reference: WSTG-INPV-01

Strategy:
  1. Identify input vectors on each URL (query params, form fields).
  2. Inject XSS payloads via HTTP requests.
  3. Use Playwright to navigate and check whether the payload is
     reflected/executed in the DOM (e.g., alert dialog triggered).
  4. Capture a screenshot as evidence on confirmed hits.
"""

from typing import List, Optional
from config import ScannerConfig
from payloads import XSS_PAYLOADS
from utils.logger import get_logger

logger = get_logger(__name__)


class XSSDetector:
    """Detect reflected and DOM-based XSS vulnerabilities."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def run(self, urls: List[str]) -> List[dict]:
        """
        Run XSS probes against all supplied URLs.

        Returns a list of finding dicts.
        """
        findings = []
        for url in urls:
            findings.extend(self._test_url(url))
        return findings

    def _test_url(self, url: str) -> List[dict]:
        """Inject payloads into all parameters of a single URL."""
        # TODO:
        #   - parse query string parameters with urllib.parse
        #   - for each param × payload: build mutated URL
        #   - call _http_probe() then _browser_probe()
        raise NotImplementedError

    def _http_probe(self, url: str, payload: str) -> bool:
        """Check if payload is reflected in the raw HTTP response body."""
        # TODO: requests.get(url), check payload in response.text
        raise NotImplementedError

    def _browser_probe(self, url: str, payload: str) -> Optional[dict]:
        """
        Navigate to URL in Playwright and detect alert dialogs or DOM injection.

        Returns a finding dict if triggered, else None.
        """
        # TODO:
        #   - page.on("dialog", ...) to catch alert()
        #   - page.goto(url)
        #   - page.screenshot() for evidence
        raise NotImplementedError
