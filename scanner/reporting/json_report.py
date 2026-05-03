"""
reporting/json_report.py — JSON report writer.

Serialises all findings to a structured JSON file for machine-readable
output, archiving, and potential import into other tooling.
"""

import json
from datetime import datetime, timezone
from typing import List
from config import ScannerConfig
from utils.logger import get_logger

logger = get_logger(__name__)


class JSONReporter:
    """Write scan findings to a JSON report file."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def write(self, findings: List[dict]) -> str:
        """
        Serialise findings to config.output as a JSON file.

        Returns the path of the written file.
        """
        # TODO:
        #   - build report dict with metadata (target, timestamp, findings)
        #   - json.dump to config.output with indent=2
        raise NotImplementedError

    def _build_report(self, findings: List[dict]) -> dict:
        """Wrap findings in a top-level report envelope."""
        return {
            "scanner": "OWASP WSTG Security Scanner",
            "target": self.config.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": findings,
        }
