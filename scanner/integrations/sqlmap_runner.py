"""
integrations/sqlmap_runner.py — sqlmap subprocess wrapper.

Runs sqlmap against URLs and forms that the scanner's SQLi detector
flagged as candidates, then parses results back into the standard
finding dict format.

Requires sqlmap to be installed and on PATH (comes with Kali Linux).
"""

import os
import json
import shutil
import subprocess
import tempfile
from typing import List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# sqlmap flags used for all runs
SQLMAP_FLAGS = [
    "--batch",          # no interactive prompts
    "--level=2",        # slightly above default coverage
    "--risk=1",         # safe payloads only
    "--threads=3",      # parallel requests
    "--output-dir",     # set below dynamically
]


class SqlmapRunner:
    """Run sqlmap and convert results into scanner findings."""

    def __init__(self, target: str, urls: List[str], forms: List[dict]):
        self.target = target
        self.urls   = urls
        self.forms  = forms

    def run(self) -> List[dict]:
        """
        Check sqlmap is available, then run it against candidate URLs.

        Returns a list of finding dicts in the scanner's standard format.
        """
        if not self._is_available():
            logger.warning(
                "sqlmap not found on PATH — skipping. "
                "Install with: sudo apt install sqlmap"
            )
            return []

        findings = []
        output_dir = tempfile.mkdtemp(prefix="sqlmap_")
        logger.info(f"Running sqlmap — output dir: {output_dir}")

        try:
            # Test each URL that has query parameters
            for url in self.urls:
                if "?" not in url:
                    continue
                findings.extend(self._run_on_url(url, output_dir))

            # Test discovered forms
            for form in self.forms:
                action = form.get("action", "")
                if action:
                    findings.extend(self._run_on_url(action, output_dir, forms=True))

        finally:
            # Clean up temp output dir
            shutil.rmtree(output_dir, ignore_errors=True)

        logger.info(f"sqlmap complete — {len(findings)} finding(s)")
        return findings

    def _run_on_url(
        self, url: str, output_dir: str, forms: bool = False
    ) -> List[dict]:
        """
        Run sqlmap against a single URL and parse the results.

        Args:
            url:        Target URL to test.
            output_dir: Directory for sqlmap output files.
            forms:      If True, pass --forms to sqlmap.

        Returns a list of finding dicts.
        """
        cmd = [
            "sqlmap",
            "-u", url,
            *SQLMAP_FLAGS,
            output_dir,
        ]

        if forms:
            cmd.append("--forms")

        logger.debug(f"sqlmap command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            logger.debug(f"sqlmap exit code: {result.returncode}")

            return self._parse_output(output_dir, url)

        except subprocess.TimeoutExpired:
            logger.warning(f"sqlmap timed out on: {url}")
        except Exception as e:
            logger.error(f"sqlmap execution failed for {url}: {e}")

        return []

    def _parse_output(self, output_dir: str, url: str) -> List[dict]:
        """
        Walk sqlmap's output directory and parse any JSON result files.

        sqlmap writes per-target JSON files under output_dir/<host>/
        """
        findings = []

        for root, _, files in os.walk(output_dir):
            for filename in files:
                if not filename.endswith(".json"):
                    continue

                path = os.path.join(root, filename)
                try:
                    with open(path) as f:
                        data = json.load(f)

                    # sqlmap JSON structure: list of injection point results
                    if isinstance(data, list):
                        for item in data:
                            finding = self._to_finding(item, url)
                            if finding:
                                findings.append(finding)
                    elif isinstance(data, dict):
                        finding = self._to_finding(data, url)
                        if finding:
                            findings.append(finding)

                except (json.JSONDecodeError, OSError) as e:
                    logger.debug(f"Could not parse sqlmap output {path}: {e}")

        return findings

    def _to_finding(self, item: dict, url: str) -> Optional[dict]:
        """
        Convert a sqlmap result item into a scanner finding dict.
        """
        # sqlmap marks vulnerable parameters with "data" entries
        if not item.get("data"):
            return None

        param    = item.get("parameter", "unknown")
        payloads = [v.get("payload", "") for v in item.get("data", {}).values()]
        technique_names = [v.get("title", "") for v in item.get("data", {}).values()]

        return {
            "type":     "SQL Injection (sqlmap confirmed)",
            "url":      url,
            "severity": "High",
            "detail":   (
                f"sqlmap confirmed SQL injection on parameter '{param}'. "
                f"Techniques: {', '.join(technique_names)}"
            ),
            "evidence": f"Payload(s): {'; '.join(payloads)}",
            "source":   "sqlmap",
        }

    @staticmethod
    def _is_available() -> bool:
        """Return True if sqlmap is on the system PATH."""
        return shutil.which("sqlmap") is not None
