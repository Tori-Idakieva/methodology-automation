"""
reporting/summary.py — Human-readable terminal summary reporter.

Uses the `rich` library to print a colour-coded findings table and
severity breakdown to stdout at the end of a scan.
"""

from typing import List
from config import ScannerConfig
from utils.logger import get_logger

logger = get_logger(__name__)


class SummaryReporter:
    """Print a formatted scan summary to the terminal."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def print(self, findings: List[dict]) -> None:
        """
        Render a rich table of findings grouped by severity.

        Columns: Severity | Type | URL | Detail
        """
        # TODO:
        #   - from rich.table import Table
        #   - from rich.console import Console
        #   - build and print table rows per finding
        #   - print severity count summary (High / Medium / Low / Info)
        raise NotImplementedError

    def _severity_counts(self, findings: List[dict]) -> dict:
        """Return a dict of {severity: count} across all findings."""
        counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
