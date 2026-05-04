"""
integrations/nikto_runner.py — Nikto subprocess wrapper.

Runs Nikto against the target and parses results back into the standard
finding dict format. Nikto covers web server misconfigurations, outdated
software headers, dangerous files, and default credentials — complementing
the scanner's own checks.

Requires Nikto to be installed and on PATH (installed in Docker image via
git clone from https://github.com/sullo/nikto).
"""

import json
import re
import shutil
import subprocess
import tempfile
import os
from typing import List, Optional
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from utils.logger import get_logger
from utils.console import console

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)

logger = get_logger(__name__)

# Nikto severity mapping based on OSVDB reference ranges
# Nikto doesn't provide native severity levels so we infer from message content
HIGH_KEYWORDS   = ["sql injection", "xss", "rce", "remote code", "command injection",
                   "directory traversal", "file inclusion", "default password"]
MEDIUM_KEYWORDS = ["directory listing", "sensitive", "backup", "config", "admin",
                   "phpinfo", "server-status", "debug", "outdated"]
LOW_KEYWORDS    = ["header", "missing", "cookie", "clickjacking", "x-frame"]


class NiktoRunner:
    """Run Nikto and convert results into scanner findings."""

    def __init__(self, target: str, auth_cookie: Optional[str] = None):
        self.target      = target
        self.auth_cookie = auth_cookie  # e.g. "PHPSESSID=abc123"

    def run(self) -> List[dict]:
        """
        Check Nikto is available, then run it against the target.

        Returns a list of finding dicts in the scanner's standard format.
        """
        nikto_bin = self._find_nikto()
        if not nikto_bin:
            logger.warning(
                "nikto not found on PATH — skipping. "
                "Ensure the Docker image was built with nikto installed."
            )
            return []

        # Write output to a temp file; Nikto appends to it if it exists
        output_fd, output_path = tempfile.mkstemp(suffix=".json", prefix="nikto_")
        os.close(output_fd)
        os.remove(output_path)   # nikto creates the file itself; remove so it's fresh

        logger.info(f"Running Nikto against: {self.target}")

        try:
            findings = self._run_nikto(nikto_bin, output_path)
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

        logger.info(f"Nikto complete — {len(findings)} finding(s)")
        return findings

    def _run_nikto(self, nikto_bin: str, output_path: str) -> List[dict]:
        """Execute Nikto and parse its JSON output."""
        cmd = [
            nikto_bin,
            "-h",     self.target,
            "-Format", "json",
            "-output", output_path,
            "-nointeractive",
            "-ask",   "no",
            # Hard cap on wall time. Nikto's full DB can run for 10+ minutes;
            # 90 s is enough to cover phpinfo.php, robots.txt, Easter Eggs,
            # admin paths, and junk-method checks without blocking the scan.
            "-maxtime", "90s",
        ]

        # Pass session cookie if we have one so Nikto can reach auth pages.
        # The -Add-header flag works across all modern Nikto versions and
        # avoids the ambiguity of -cookie / -cookies flag naming differences.
        if self.auth_cookie:
            cmd += ["-Add-header", f"Cookie: {self.auth_cookie}"]

        logger.debug(f"Nikto command: {' '.join(cmd)}")

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
                                title="[cyan]nikto[/cyan]",
                                border_style="cyan",
                                padding=(0, 1),
                            )
                        )
                proc.wait(timeout=300)

            logger.debug(f"Nikto exit code: {proc.returncode}")

        except subprocess.TimeoutExpired:
            logger.warning("Nikto timed out after 300s")
            try:
                proc.kill()
            except Exception:
                pass
            return []
        except Exception as e:
            logger.error(f"Nikto execution failed: {e}")
            return []

        stdout_text = "\n".join(stdout_lines)

        # If the JSON file was not written, try to parse stdout as JSON
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            logger.debug("Nikto output file absent/empty — trying stdout")
            return self._parse_content(stdout_text, self.target)

        return self._parse_file(output_path)

    def _parse_file(self, output_path: str) -> List[dict]:
        """Read and parse the Nikto JSON output file."""
        try:
            with open(output_path) as f:
                content = f.read().strip()
        except OSError as e:
            logger.error(f"Could not read Nikto output: {e}")
            return []

        if not content:
            logger.warning("Nikto output file is empty")
            return []

        return self._parse_content(content, self.target)

    def _parse_content(self, content: str, host: str) -> List[dict]:
        """
        Parse Nikto output into scanner findings.

        Tries JSON first (Nikto ≥ 2.1.5 with -Format json). If the content
        is not valid JSON, falls back to parsing Nikto's plain-text format
        where each finding line starts with '+ '.
        """
        findings = []
        content = content.strip()
        if not content:
            return findings

        # ── Try JSON ──────────────────────────────────────────────────────
        data = None
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # NDJSON (one JSON object per line)?
            ndjson_items = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ndjson_items.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            if ndjson_items:
                data = ndjson_items

        if data is not None:
            hosts = data if isinstance(data, list) else [data]
            for host_obj in hosts:
                vulns = host_obj.get("vulnerabilities") or host_obj.get("issues") or []
                target_host = host_obj.get("host", host)
                for vuln in vulns:
                    finding = self._to_finding(vuln, target_host)
                    if finding:
                        findings.append(finding)
            return self._deduplicate_headers(findings)

        # ── Fallback: plain-text parser ───────────────────────────────────
        # Nikto v2.x plain-text format:
        #   + OSVDB-3268: /path/: message
        #   + /path: message
        #   + Server: Apache/2.4
        # Lines starting with '-' are headers/footers; skip them.
        logger.debug("Nikto output is plain text — using text parser")
        # Nikto ≥ 2.6 uses bracketed reference IDs: "+ [013587] /path: msg"
        # Older versions used OSVDB:             "+ OSVDB-3268: /path: msg"
        # We match both, plus bare lines:        "+ /path: msg"
        _ref_re   = re.compile(r"^\+\s+\[(\d+)\]\s+(.+)$")
        _osvdb_re = re.compile(r"^\+\s+OSVDB-(\d+):\s+(.+)$")
        _plain_re = re.compile(r"^\+\s+(.+)$")
        # Metadata / summary lines we want to skip (not real findings).
        # These appear in Nikto's plain-text output as informational context
        # rather than actual vulnerability reports.
        _SKIP_PREFIXES = (
            "Target IP:", "Target Hostname:", "Target Port:",
            "Start Time:", "End Time:",
            "Platform:",          # OS fingerprint header line
            "Server:",            # echoed from the response header
            "SSL Info:",
            "Scan terminated",
        )
        # Summary / footer lines: "3 requests: 0 errors…" or "1 host(s) tested"
        _SUMMARY_RE = re.compile(
            r"^(?:\d+ requests?:|\d+ host\(s\) tested|host\(s\) tested)",
            re.IGNORECASE,
        )

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line.startswith("+"):
                continue

            # Skip metadata info lines
            stripped = line.lstrip("+ ").strip()
            if any(stripped.startswith(p) for p in _SKIP_PREFIXES):
                continue
            if _SUMMARY_RE.match(stripped):
                continue

            ref_id = ""
            msg    = ""

            m = _ref_re.match(line)
            if m:
                ref_id = m.group(1)
                msg    = m.group(2).strip()
            else:
                m = _osvdb_re.match(line)
                if m:
                    ref_id = m.group(1)
                    msg    = m.group(2).strip()
                else:
                    m = _plain_re.match(line)
                    if m:
                        msg = m.group(1).strip()

            if not msg:
                continue

            severity = self._infer_severity(msg)
            evidence_parts = ["Method: GET"]
            if ref_id:
                evidence_parts.append(f"Ref: {ref_id}")

            findings.append({
                "type":     "Nikto Finding",
                "url":      host,
                "severity": severity,
                "detail":   msg,
                "evidence": " | ".join(evidence_parts),
                "source":   "nikto",
            })

        return self._deduplicate_headers(findings)

    @staticmethod
    def _deduplicate_headers(findings: List[dict]) -> List[dict]:
        """
        Remove Nikto's 'suggested security header missing' findings.

        The scanner's own HeadersDetector already reports these at Medium
        severity with per-header context. Keeping the Nikto versions creates
        duplicate Low-severity noise for the same missing headers.
        This filter runs regardless of whether Nikto produced JSON or plain
        text output, so the deduplication is always applied.
        """
        return [
            f for f in findings
            if "suggested security header missing" not in f.get("detail", "").lower()
        ]

    def _to_finding(self, vuln: dict, host: str) -> Optional[dict]:
        """Convert a Nikto vulnerability entry into a scanner finding dict."""
        msg    = vuln.get("msg", "").strip()
        url    = vuln.get("url", "/")
        method = vuln.get("method", "GET")
        osvdb  = vuln.get("osvdbid", "")

        if not msg:
            return None

        full_url = (
            host.rstrip("/") + "/" + url.lstrip("/")
            if not url.startswith("http") else url
        )
        severity = self._infer_severity(msg)

        evidence_parts = [f"Method: {method}"]
        if osvdb:
            evidence_parts.append(f"OSVDB-{osvdb}")

        return {
            "type":     "Nikto Finding",
            "url":      full_url,
            "severity": severity,
            "detail":   msg,
            "evidence": " | ".join(evidence_parts),
            "source":   "nikto",
        }

    @staticmethod
    def _infer_severity(msg: str) -> str:
        """Infer severity from the Nikto message text."""
        msg_lower = msg.lower()
        for keyword in HIGH_KEYWORDS:
            if keyword in msg_lower:
                return "High"
        for keyword in MEDIUM_KEYWORDS:
            if keyword in msg_lower:
                return "Medium"
        for keyword in LOW_KEYWORDS:
            if keyword in msg_lower:
                return "Low"
        return "Info"

    @staticmethod
    def _find_nikto() -> Optional[str]:
        """
        Locate the nikto executable.

        Checks PATH first (shutil.which), then falls back to the Docker
        image install path at /opt/nikto/program/nikto.pl.
        """
        on_path = shutil.which("nikto")
        if on_path:
            return on_path
        fallback = "/opt/nikto/program/nikto.pl"
        if os.path.exists(fallback):
            return fallback
        return None
