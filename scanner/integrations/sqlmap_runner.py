"""
integrations/sqlmap_runner.py — sqlmap subprocess wrapper.

Runs sqlmap against URLs and forms that the scanner's SQLi detector
flagged as candidates, then parses results back into the standard
finding dict format.

Requires sqlmap to be installed and on PATH (installed via pip in Docker).
"""

import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from utils.logger import get_logger
from utils.console import console

logger = get_logger(__name__)

# sqlmap flags used for all runs
SQLMAP_FLAGS = [
    "--batch",          # no interactive prompts
    "--level=2",        # slightly above default coverage
    "--risk=1",         # safe payloads only
    "--threads=3",      # parallel requests
]

# Strip ANSI escape sequences from sqlmap output for clean display
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Patterns that confirm a parameter is injectable (from sqlmap stdout)
# e.g. "[INFO] GET parameter 'id' is 'Boolean-based blind' injectable"
# e.g. "[INFO] POST parameter 'username' is 'UNION query' injectable"
_INJECT_RE = re.compile(
    r"\[(?:INFO|WARNING)\]\s+(?:GET|POST|URI|Cookie)?\s*parameter\s+'([^']+)'\s+is\s+'([^']+)'\s+injectable",
    re.IGNORECASE,
)
# e.g. "[INFO] the back-end DBMS is MySQL"
_DBMS_RE = re.compile(r"\[INFO\]\s+the back-end DBMS is\s+(.+)", re.IGNORECASE)


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class SqlmapRunner:
    """Run sqlmap and convert results into scanner findings."""

    def __init__(
        self,
        target: str,
        urls: List[str],
        forms: List[dict],
        auth_cookie: Optional[str] = None,
    ):
        self.target      = target
        self.urls        = urls
        self.forms       = forms
        self.auth_cookie = auth_cookie  # e.g. "PHPSESSID=abc123"

    def run(self) -> List[dict]:
        """
        Check sqlmap is available, then run it against candidate URLs.

        Streams sqlmap's output live via a Rich panel.
        Returns a list of finding dicts in the scanner's standard format.
        """
        if not self._is_available():
            logger.warning(
                "sqlmap not found on PATH — skipping. "
                "Ensure the Docker image was built with sqlmap installed."
            )
            return []

        findings   = []
        output_dir = tempfile.mkdtemp(prefix="sqlmap_")
        logger.info(f"Running sqlmap — output dir: {output_dir}")

        # Collect URLs to test (parameterised URLs + form actions)
        targets      = [u for u in self.urls if "?" in u]
        form_actions = list({
            f["action"] for f in self.forms
            if f.get("action") and f["action"] != self.target
        })

        total = len(targets) + len(form_actions)
        if total == 0:
            logger.info("sqlmap: no parameterised URLs or forms to test")
            shutil.rmtree(output_dir, ignore_errors=True)
            return []

        try:
            for i, url in enumerate(targets, 1):
                logger.debug(f"sqlmap [{i}/{total}]: {url}")
                findings.extend(
                    self._run_on_url(url, output_dir, label=f"sqlmap [{i}/{total}]")
                )
            for i, action in enumerate(form_actions, len(targets) + 1):
                logger.debug(f"sqlmap [{i}/{total}] (form): {action}")
                findings.extend(
                    self._run_on_url(
                        action, output_dir,
                        forms=True,
                        label=f"sqlmap [{i}/{total}] — forms",
                    )
                )
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

        logger.info(f"sqlmap complete — {len(findings)} finding(s)")
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_on_url(
        self,
        url: str,
        output_dir: str,
        forms: bool = False,
        label: str = "sqlmap",
    ) -> List[dict]:
        """Run sqlmap against a single URL, streaming output live."""
        cmd = [
            "sqlmap",
            "-u", url,
            *SQLMAP_FLAGS,
            "--output-dir", output_dir,
        ]

        if forms:
            cmd.append("--forms")

        if self.auth_cookie:
            cmd += ["--cookie", self.auth_cookie]

        logger.debug(f"sqlmap command: {' '.join(cmd)}")

        stdout_lines: List[str] = []

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            with Live(console=console, refresh_per_second=4, transient=True) as live:
                for raw_line in iter(proc.stdout.readline, ""):
                    line = _strip_ansi(raw_line).rstrip()
                    if line:
                        stdout_lines.append(line)
                        recent = stdout_lines[-6:]
                        display = Text()
                        for l in recent:
                            display.append(l + "\n", style="dim")
                        live.update(
                            Panel(
                                display,
                                title=f"[cyan]{label}[/cyan]",
                                border_style="cyan",
                                padding=(0, 1),
                            )
                        )
                proc.wait(timeout=180)

            logger.debug(f"sqlmap exit code: {proc.returncode}")

        except subprocess.TimeoutExpired:
            logger.warning(f"sqlmap timed out on: {url}")
            try:
                proc.kill()
            except Exception:
                pass
            return []
        except Exception as e:
            logger.error(f"sqlmap execution failed for {url}: {e}")
            return []

        return self._parse_stdout(stdout_lines, url)

    def _parse_stdout(self, lines: List[str], url: str) -> List[dict]:
        """
        Parse sqlmap's stdout for injection confirmation messages.

        sqlmap does not write JSON result files by default. Instead we
        scan its output lines for the "[INFO] parameter '...' is '...' injectable"
        pattern, which sqlmap prints whenever it confirms a vulnerability.
        """
        findings = []
        # Detect DBMS from output for richer evidence
        dbms = "unknown"
        for line in lines:
            m = _DBMS_RE.search(line)
            if m:
                dbms = m.group(1).strip()
                break

        seen_params: set = set()
        for line in lines:
            m = _INJECT_RE.search(line)
            if not m:
                continue
            param, technique = m.group(1), m.group(2)
            key = (url, param)
            if key in seen_params:
                continue
            seen_params.add(key)
            logger.warning(
                f"sqlmap confirmed injection — param: '{param}', "
                f"technique: '{technique}', url: {url}"
            )
            findings.append({
                "type":     "SQL Injection (sqlmap confirmed)",
                "url":      url,
                "severity": "High",
                "detail":   (
                    f"sqlmap confirmed SQL injection on parameter '{param}'. "
                    f"Technique: {technique}. Back-end DBMS: {dbms}."
                ),
                "evidence": f"Technique: {technique}",
                "source":   "sqlmap",
            })

        return findings

    @staticmethod
    def _is_available() -> bool:
        """Return True if sqlmap is on the system PATH."""
        return shutil.which("sqlmap") is not None
