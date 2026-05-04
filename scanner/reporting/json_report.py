"""
reporting/json_report.py — JSON report writer.

Serialises all findings to a structured JSON file for machine-readable
output, archiving, and potential import into other tooling.
"""

import os
from datetime import datetime, timezone
from typing import List
from config import ScannerConfig
from utils.file_handler import write_json, REPORTS_DIR
from utils.logger import get_logger
from reporting import severity_counts

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
        path = os.path.join(REPORTS_DIR, f"{self.config.output}.json")
        report = self._build_report(findings)
        write_json(path, report)
        logger.info(f"JSON report written to: {path}")
        return path

    def _build_report(self, findings: List[dict]) -> dict:
        """Wrap findings in a top-level report envelope."""
        counts = severity_counts(findings)
        return {
            "scanner":        "OWASP WSTG Security Scanner",
            "target":         self.config.target,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "severity_counts": counts,
            "findings":       findings,
        }

