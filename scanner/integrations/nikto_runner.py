"""
integrations/nikto_runner.py — Nikto subprocess wrapper.

Runs Nikto against the target and parses results back into the standard
finding dict format. Nikto covers web server misconfigurations, outdated
software headers, dangerous files, and default credentials — complementing
the scanner's own checks.

Requires Nikto to be installed and on PATH (comes with Kali Linux).
"""

import json
import shutil
import subprocess
import tempfile
import os
from typing import List, Optional
from utils.logger import get_logger

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

    def __init__(self, target: str):
        self.target = target

    def run(self) -> List[dict]:
        """
        Check Nikto is available, then run it against the target.

        Returns a list of finding dicts in the scanner's standard format.
        """
        if not self._is_available():
            logger.warning(
                "nikto not found on PATH — skipping. "
                "Install with: sudo apt install nikto"
            )
            return []

        output_file = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, prefix="nikto_"
        )
        output_path = output_file.name
        output_file.close()

        logger.info(f"Running Nikto against: {self.target}")

        try:
            findings = self._run_nikto(output_path)
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

        logger.info(f"Nikto complete — {len(findings)} finding(s)")
        return findings

    def _run_nikto(self, output_path: str) -> List[dict]:
        """Execute Nikto and parse its JSON output."""
        cmd = [
            "nikto",
            "-h",     self.target,
            "-Format", "json",
            "-output", output_path,
            "-nointeractive",
            "-ask",   "no",
        ]

        logger.debug(f"Nikto command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )
            logger.debug(f"Nikto exit code: {result.returncode}")

        except subprocess.TimeoutExpired:
            logger.warning("Nikto timed out")
            return []
        except Exception as e:
            logger.error(f"Nikto execution failed: {e}")
            return []

        return self._parse_output(output_path)

    def _parse_output(self, output_path: str) -> List[dict]:
        """
        Parse Nikto's JSON output file into scanner findings.

        Nikto JSON structure:
        {
          "host": "...",
          "vulnerabilities": [
            { "id": "...", "method": "GET", "url": "...", "msg": "..." }
          ]
        }
        """
        findings = []

        if not os.path.exists(output_path):
            logger.warning("Nikto produced no output file")
            return []

        try:
            with open(output_path) as f:
                content = f.read().strip()

            if not content:
                logger.warning("Nikto output file is empty")
                return []

            data = json.loads(content)

            # Nikto may return a list of host objects or a single object
            hosts = data if isinstance(data, list) else [data]

            for host in hosts:
                vulns = host.get("vulnerabilities", [])
                for vuln in vulns:
                    finding = self._to_finding(vuln, host.get("host", self.target))
                    if finding:
                        findings.append(finding)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Nikto JSON output: {e}")
        except OSError as e:
            logger.error(f"Could not read Nikto output: {e}")

        return findings

    def _to_finding(self, vuln: dict, host: str) -> Optional[dict]:
        """Convert a Nikto vulnerability entry into a scanner finding dict."""
        msg    = vuln.get("msg", "").strip()
        url    = vuln.get("url", "/")
        method = vuln.get("method", "GET")
        osvdb  = vuln.get("osvdbid", "")

        if not msg:
            return None

        full_url = host.rstrip("/") + "/" + url.lstrip("/") if not url.startswith("http") else url
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
        """
        Infer severity from the Nikto message text.

        Nikto doesn't provide native severity ratings so we classify based
        on keywords in the message.
        """
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
    def _is_available() -> bool:
        """Return True if nikto is on the system PATH."""
        return shutil.which("nikto") is not None
