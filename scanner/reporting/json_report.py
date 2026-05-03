"""
reporting/json_report.py — JSON report writer.

Serialises all findings to a structured JSON file for machine-readable
output, archiving, and potential import into other tooling.
"""

import json
from datetime import datetime, timezone
from typing import List
from config import ScannerConfig
from utils.file_handler import write_json
from utils.logger import get_logger

logger = get_logger(__name__)


class JSONReporter:
    """Write scan findings to a JSON report file."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def write(self, findings: List[dict]) -> str:
        """
        Serialise findings to a JSON file at <config.output>.json.

        Returns the path of the written file.
        """
        path = f"{self.config.output}.json"
        report = self._build_report(findings)
        write_json(path, report)
        logger.info(f"JSON report written to: {path}")
        return path

    def _build_report(self, findings: List[dict]) -> dict:
        """Wrap findings in a top-level report envelope."""
        counts = self._severity_counts(findings)
        return {
            "scanner":        "OWASP WSTG Security Scanner",
            "target":         self.config.target,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "severity_counts": counts,
            "findings":       findings,
        }

    def _severity_counts(self, findings: List[dict]) -> dict:
        """Return a dict of {severity: count} across all findings."""
        counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
