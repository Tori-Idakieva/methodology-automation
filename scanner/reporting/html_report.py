"""
reporting/html_report.py — HTML report writer.

Generates a self-contained, styled HTML report from scan findings.
Easier to read than JSON — intended for sharing and presentation.
"""

from typing import List
from datetime import datetime, timezone
from config import ScannerConfig
from utils.logger import get_logger

logger = get_logger(__name__)

# Severity badge colours
SEVERITY_COLOURS = {
    "High":   "#e74c3c",
    "Medium": "#e67e22",
    "Low":    "#f1c40f",
    "Info":   "#3498db",
}


class HTMLReporter:
    """Write scan findings to a styled HTML report file."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def write(self, findings: List[dict], path: str) -> str:
        """
        Render findings as a self-contained HTML file and write to `path`.

        Returns the path of the written file.
        """
        # TODO:
        #   - call _render(findings) to get HTML string
        #   - write to path
        raise NotImplementedError

    def _render(self, findings: List[dict]) -> str:
        """
        Build and return the full HTML document as a string.

        Structure:
          - Header with scan metadata (target, timestamp, total findings)
          - Severity summary bar (counts per severity)
          - Findings table (severity badge | type | url | detail | evidence)
        """
        # TODO: build HTML using f-strings or a simple template
        raise NotImplementedError

    def _severity_badge(self, severity: str) -> str:
        """Return an inline-styled HTML badge span for the given severity."""
        colour = SEVERITY_COLOURS.get(severity, "#888")
        return (
            f'<span style="background:{colour};color:#fff;'
            f'padding:2px 8px;border-radius:4px;font-size:0.85em;">'
            f'{severity}</span>'
        )
