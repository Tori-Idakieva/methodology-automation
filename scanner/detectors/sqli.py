"""
detectors/sqli.py — SQL Injection (SQLi) detector.

OWASP WSTG reference: WSTG-INPV-05

Strategy:
  1. Inject SQLi payloads into URL query parameters.
  2. Look for database error signatures in HTTP responses (error-based).
  3. Compare response lengths/content for boolean-based blind differences.
  4. Log payloads and response snippets as evidence.
"""

from typing import List, Optional
from config import ScannerConfig
from payloads import SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES
from utils.logger import get_logger

logger = get_logger(__name__)


class SQLiDetector:
    """Detect SQL injection vulnerabilities via error-based and boolean probes."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def run(self, urls: List[str]) -> List[dict]:
        """
        Run SQLi probes against all supplied URLs.

        Returns a list of finding dicts.
        """
        findings = []
        for url in urls:
            findings.extend(self._test_url(url))
        return findings

    def _test_url(self, url: str) -> List[dict]:
        """Inject payloads into all parameters of a single URL."""
        # TODO:
        #   - parse query string params
        #   - for each param × payload: build mutated URL
        #   - call _error_based_probe() and _boolean_probe()
        raise NotImplementedError

    def _error_based_probe(self, url: str, payload: str) -> Optional[dict]:
        """
        Send injected request and scan response for DB error signatures.

        Returns a finding dict if a signature matches, else None.
        """
        # TODO:
        #   - requests.get(url)
        #   - check response.text.lower() against SQLI_ERROR_SIGNATURES
        raise NotImplementedError

    def _boolean_probe(self, url: str, param: str, payload: str) -> Optional[dict]:
        """
        Compare baseline response with injected response to detect
        boolean-based blind SQLi via content-length or body differences.

        Returns a finding dict if anomaly detected, else None.
        """
        # TODO:
        #   - baseline GET (no payload)
        #   - injected GET (with TRUE condition payload)
        #   - compare len(response.text) or hash; flag large divergence
        raise NotImplementedError
