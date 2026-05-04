"""
reporting/summary.py — Human-readable terminal summary reporter.

Uses the `rich` library to print a colour-coded findings table and
severity breakdown to stdout at the end of a scan.
"""

from rich.table import Table
from rich.text import Text
from rich import box
from typing import List
from config import ScannerConfig
from utils.logger import get_logger
from utils.console import console
from reporting import severity_counts, SEVERITY_ORDER

logger = get_logger(__name__)

# Map severity to rich colour names
SEVERITY_STYLES = {
    "High":   "bold red",
    "Medium": "bold yellow",
    "Low":    "bold cyan",
    "Info":   "bold blue",
}


class SummaryReporter:
    """Print a formatted scan summary to the terminal."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def print(self, findings: List[dict]) -> None:
        """
        Render a rich table of all findings, then print a severity count summary.

        Columns: Severity | Type | URL | Detail
        """
        console.rule("[bold white]Scan Complete")

        if not findings:
            console.print("\n[bold green]No vulnerabilities found.[/bold green]\n")
            return

        # Build findings table
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white",
            show_lines=True,
            expand=True,
        )

        table.add_column("Severity",  style="bold", width=10, no_wrap=True)
        table.add_column("Type",      style="white", width=35)
        table.add_column("URL",       style="dim",   width=45, overflow="fold")
        table.add_column("Detail",    style="white", overflow="fold")

        # Sort findings: High → Medium → Low → Info
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 4)
        )

        for finding in sorted_findings:
            severity = finding.get("severity", "Info")
            style    = SEVERITY_STYLES.get(severity, "white")

            table.add_row(
                Text(severity, style=style),
                finding.get("type",   "—"),
                finding.get("url",    "—"),
                finding.get("detail", "—"),
            )

        console.print()
        console.print(table)

        # Severity count summary
        self._print_counts(findings)

    def _print_counts(self, findings: List[dict]) -> None:
        """Print a one-line severity breakdown below the table."""
        counts = severity_counts(findings)
        total  = len(findings)

        parts = []
        for severity, style in SEVERITY_STYLES.items():
            count = counts.get(severity, 0)
            parts.append(f"[{style}]{severity}: {count}[/{style}]")

        summary_line = "   ".join(parts) + f"   [white]Total: {total}[/white]"
        console.print()
        console.print(summary_line)
        console.print()

