"""
detectors/sqli.py — SQL Injection (SQLi) detector.

OWASP WSTG reference: WSTG-INPV-05

Strategy:
  1. Inject SQLi payloads into each URL query parameter individually.
  2. Error-based: look for database error signatures in the HTTP response body.
  3. Boolean-based blind: compare baseline response length against injected
     response — a significant difference suggests the query changed behaviour.
  4. Also test form injection vectors discovered during crawling.
  5. Log payloads and response snippets as evidence.
"""

import requests
from urllib.parse import urlparse, parse_qs
from typing import List, Optional
from config import ScannerConfig
from payloads import SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES
from utils.logger import get_logger
from utils.http import build_session
from utils.url import inject_param

logger = get_logger(__name__)

# How much the response length must differ (%) to flag boolean-based blind SQLi
BOOLEAN_DIFF_THRESHOLD = 0.20  # 20%

# URL parameters that are typically used for file inclusion / path traversal,
# not SQL queries. Injecting SQL syntax into these causes "file not found"
# responses (dramatic length change) that look like boolean-based SQLi but
# are actually false positives. Skip them for SQL injection testing.
_FILE_INCLUSION_PARAMS = frozenset({
    "page", "file", "doc", "path", "dir", "include", "filepath",
    "template", "load", "view", "pg", "p", "module", "section",
})


class SQLiDetector:
    """Detect SQL injection vulnerabilities via error-based and boolean probes."""

    def __init__(self, config: ScannerConfig, forms: Optional[List[dict]] = None):
        self.config = config
        self.forms = forms or []          # form vectors from the crawlers
        self.session = build_session(config)

    def run(self, urls: List[str]) -> List[dict]:
        """
        Run SQLi probes against URL query parameters and discovered forms.

        Returns a list of finding dicts.
        """
        findings = []

        # Test URL query parameters
        for url in urls:
            if "?" in url:
                findings.extend(self._test_url(url))

        # Test form injection vectors
        for form in self.forms:
            findings.extend(self._test_form(form))

        return findings

    # ------------------------------------------------------------------
    # URL parameter testing
    # ------------------------------------------------------------------

    def _test_url(self, url: str) -> List[dict]:
        """
        Inject payloads into each query parameter of `url` one at a time.

        Tests each parameter individually so we can identify exactly which
        one is vulnerable.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        # Get baseline response for boolean comparison
        baseline = self._fetch(url)
        if baseline is None:
            return findings

        for param in params:
            # Skip parameters commonly used for file inclusion / path traversal —
            # injecting SQL syntax into these causes "file not found" responses
            # (large length change) that look like boolean-based blind SQLi but
            # are actually false positives.
            if param.lower() in _FILE_INCLUSION_PARAMS:
                logger.debug(f"SQLi: skipping file-inclusion-like parameter '{param}' on {url}")
                continue

            payloads = SQLI_PAYLOADS[:self.config.max_payloads_per_param]
            for payload in payloads:
                injected_url = inject_param(url, param, payload)
                logger.debug(f"SQLi probe [{param}]: {injected_url}")

                # Error-based probe
                finding = self._error_based_probe(injected_url, param, payload)
                if finding:
                    findings.append(finding)
                    break   # confirmed on this param, no need to try more payloads

                # Boolean-based blind probe
                finding = self._boolean_probe(
                    url, injected_url, param, payload, baseline
                )
                if finding:
                    findings.append(finding)
                    break

        return findings

    # ------------------------------------------------------------------
    # Form testing
    # ------------------------------------------------------------------

    # URL path segments whose forms accept OS commands, not SQL queries.
    # Injecting SQL syntax into these causes the server to try to execute
    # the payload as a shell command, which hangs until the OS timeout.
    _CMD_INJECTION_PATHS = frozenset({"exec", "cmd", "command", "ping", "shell"})

    def _test_form(self, form: dict) -> List[dict]:
        """
        Inject SQLi payloads into each input field of a discovered form.
        """
        findings = []
        action  = form.get("action", "")
        method  = form.get("method", "get").lower()
        inputs  = form.get("inputs", [])

        if not action or not inputs:
            return findings

        # Skip forms whose action URL looks like a command-injection endpoint.
        # These don't query a SQL database and will timeout waiting for the OS
        # to process injected shell syntax (e.g. DVWA's exec/ endpoint).
        from urllib.parse import urlparse as _up
        _path_parts = set(_up(action).path.strip("/").split("/"))
        if _path_parts & self._CMD_INJECTION_PATHS:
            logger.debug(f"SQLi: skipping command-injection-like form: {action}")
            return findings

        for field in inputs:
            payloads = SQLI_PAYLOADS[:self.config.max_payloads_per_param]
            for payload in payloads:
                data = {i: "test" for i in inputs}
                data[field] = payload

                logger.debug(f"SQLi form probe [{field}] → {action}")
                response = self._submit_form(action, method, data)

                if response is None:
                    continue

                finding = self._check_error_signatures(
                    url=action,
                    param=field,
                    payload=payload,
                    body=response.text,
                )
                if finding:
                    findings.append(finding)
                    break

        return findings

    # ------------------------------------------------------------------
    # Probes
    # ------------------------------------------------------------------

    def _error_based_probe(
        self, url: str, param: str, payload: str
    ) -> Optional[dict]:
        """
        Fetch the injected URL and scan the response body for DB error strings.

        Returns a finding dict if a signature matches, else None.
        """
        response = self._fetch(url)
        if response is None:
            return None

        return self._check_error_signatures(url, param, payload, response.text)

    def _boolean_probe(
        self,
        original_url: str,
        injected_url: str,
        param: str,
        payload: str,
        baseline: requests.Response,
    ) -> Optional[dict]:
        """
        Compare the baseline response length against the injected response.

        A significant difference suggests the injected condition changed the
        SQL query behaviour — a strong indicator of boolean-based blind SQLi.
        """
        response = self._fetch(injected_url)
        if response is None:
            return None

        baseline_len  = len(baseline.text)
        injected_len  = len(response.text)

        if baseline_len == 0:
            return None

        diff_ratio = abs(baseline_len - injected_len) / baseline_len

        if diff_ratio >= BOOLEAN_DIFF_THRESHOLD:
            logger.warning(
                f"Boolean SQLi candidate [{param}] on {original_url} "
                f"— response length changed by {diff_ratio:.0%}"
            )
            return {
                "type":     "SQL Injection (Boolean-Based Blind)",
                "url":      original_url,
                "severity": "High",
                "detail":   (
                    f"Parameter '{param}' caused a {diff_ratio:.0%} change in "
                    f"response length when injected with a boolean condition. "
                    f"This may indicate blind SQL injection."
                ),
                "evidence": (
                    f"Payload: {payload} | "
                    f"Baseline length: {baseline_len} | "
                    f"Injected length: {injected_len}"
                ),
            }

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_error_signatures(
        self, url: str, param: str, payload: str, body: str
    ) -> Optional[dict]:
        """
        Scan a response body for known database error strings.

        Returns a finding dict if any signature matches, else None.
        """
        body_lower = body.lower()
        for signature in SQLI_ERROR_SIGNATURES:
            if signature in body_lower:
                logger.warning(
                    f"SQLi error signature found [{param}] on {url} "
                    f"— matched: '{signature}'"
                )
                # Extract a short snippet around the match for evidence
                idx = body_lower.index(signature)
                snippet = body[max(0, idx - 40): idx + len(signature) + 40].strip()
                return {
                    "type":     "SQL Injection (Error-Based)",
                    "url":      url,
                    "severity": "High",
                    "detail":   (
                        f"Parameter '{param}' triggered a database error response. "
                        f"Matched signature: '{signature}'"
                    ),
                    "evidence": f"Payload: {payload} | Response snippet: ...{snippet}...",
                }
        return None

    def _fetch(self, url: str) -> Optional[requests.Response]:
        """GET `url` and return the response, or None on failure."""
        try:
            return self.session.get(
                url,
                timeout=self.config.request_timeout,
                allow_redirects=True,
            )
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error: {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {url} — {e}")
        return None

    def _submit_form(
        self, action: str, method: str, data: dict
    ) -> Optional[requests.Response]:
        """Submit a form with the given data using GET or POST."""
        try:
            if method == "post":
                return self.session.post(
                    action, data=data, timeout=self.config.request_timeout
                )
            else:
                return self.session.get(
                    action, params=data, timeout=self.config.request_timeout
                )
        except requests.exceptions.RequestException as e:
            logger.error(f"Form submission failed: {action} — {e}")
        return None
