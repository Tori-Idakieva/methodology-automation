"""
integrations/nvd_api.py — NVD CVE API 2.0 enrichment.

Enriches scanner findings with:
  - CWE ID (Common Weakness Enumeration) via static mapping
  - OWASP WSTG reference via static mapping
  - Related CVE count and CVSS severity from the NVD API

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit:   5 requests / 30 seconds without an API key
"""

import time
import requests
from typing import List, Optional
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, MofNCompleteColumn, TimeElapsedColumn,
)
from utils.logger import get_logger
from utils.console import console

logger = get_logger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 6  # seconds between requests to stay within rate limit

# ---------------------------------------------------------------------------
# Static CWE + OWASP WSTG mapping
# Keyed on substrings of finding["type"] for flexible matching
# ---------------------------------------------------------------------------
FINDING_METADATA = {
    "Cross-Site Scripting": {
        "cwe_id":    "CWE-79",
        "cwe_name":  "Improper Neutralisation of Input During Web Page Generation",
        "wstg_ref":  "WSTG-INPV-01",
        "owasp_top10": "A03:2021 - Injection",
    },
    "SQL Injection": {
        "cwe_id":    "CWE-89",
        "cwe_name":  "Improper Neutralisation of Special Elements used in an SQL Command",
        "wstg_ref":  "WSTG-INPV-05",
        "owasp_top10": "A03:2021 - Injection",
    },
    "Missing Security Header": {
        "cwe_id":    "CWE-693",
        "cwe_name":  "Protection Mechanism Failure",
        "wstg_ref":  "WSTG-CONF-07",
        "owasp_top10": "A05:2021 - Security Misconfiguration",
    },
    "Weak Security Header": {
        "cwe_id":    "CWE-693",
        "cwe_name":  "Protection Mechanism Failure",
        "wstg_ref":  "WSTG-CONF-07",
        "owasp_top10": "A05:2021 - Security Misconfiguration",
    },
    "Weak Content-Security-Policy": {
        "cwe_id":    "CWE-693",
        "cwe_name":  "Protection Mechanism Failure",
        "wstg_ref":  "WSTG-CONF-07",
        "owasp_top10": "A05:2021 - Security Misconfiguration",
    },
    "Directory Listing": {
        "cwe_id":    "CWE-548",
        "cwe_name":  "Exposure of Information Through Directory Listing",
        "wstg_ref":  "WSTG-CONF-04",
        "owasp_top10": "A05:2021 - Security Misconfiguration",
    },
    "Missing X-Frame-Options": {
        "cwe_id":    "CWE-1021",
        "cwe_name":  "Improper Restriction of Rendered UI Layers or Frames",
        "wstg_ref":  "WSTG-CONF-07",
        "owasp_top10": "A05:2021 - Security Misconfiguration",
    },
}


class NVDEnricher:
    """Enrich findings with CWE metadata and NVD CVE API data."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._cve_cache: dict = {}   # cache per CWE to avoid duplicate API calls
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SecurityScanner/1.0 (academic research)",
        })
        if api_key:
            self.session.headers["apiKey"] = api_key

    def enrich(self, findings: List[dict]) -> List[dict]:
        """
        Add CWE, OWASP, and NVD CVE data to each finding in-place.

        Applies a static CWE + WSTG mapping first, then queries the NVD
        CVE API once per unique CWE. A Rich progress bar shows how many
        CWE lookups remain — each one carries a 6-second rate-limit delay.

        Returns the enriched findings list.
        """
        if not findings:
            return findings

        # Pre-compute the set of unique CWEs we will need to query so we
        # can give the progress bar an accurate total upfront.
        pending_cwes: set = set()
        for finding in findings:
            metadata = self._match_metadata(finding.get("type", ""))
            if metadata:
                pending_cwes.add(metadata["cwe_id"])

        logger.info(
            f"Enriching {len(findings)} finding(s) — "
            f"{len(pending_cwes)} unique CWE(s) to query"
        )

        queried_cwes: set = set()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,   # clear bar when done so the terminal stays clean
        ) as progress:
            task = progress.add_task(
                "Querying NVD CVE API...",
                total=len(pending_cwes) if pending_cwes else 1,
            )

            for finding in findings:
                finding_type = finding.get("type", "")
                metadata = self._match_metadata(finding_type)

                if metadata:
                    # Apply static CWE + WSTG fields
                    finding["cwe_id"]      = metadata["cwe_id"]
                    finding["cwe_name"]    = metadata["cwe_name"]
                    finding["wstg_ref"]    = metadata["wstg_ref"]
                    finding["owasp_top10"] = metadata["owasp_top10"]
                    finding["nvd_url"]     = (
                        "https://nvd.nist.gov/vuln/search/results"
                        f"?form_type=Advanced&cwe_id={metadata['cwe_id']}"
                    )

                    cwe_id = metadata["cwe_id"]

                    # Query NVD API once per unique CWE, then reuse the cache
                    if cwe_id not in queried_cwes:
                        progress.update(task, description=f"NVD API — {cwe_id}")
                        if queried_cwes:
                            time.sleep(REQUEST_DELAY)   # respect rate limit
                        nvd_data = self._fetch_nvd(cwe_id)
                        self._cve_cache[cwe_id] = nvd_data
                        queried_cwes.add(cwe_id)
                        progress.advance(task)

                    nvd_data = self._cve_cache.get(cwe_id, {})
                    finding["cve_count"]      = nvd_data.get("cve_count",      "N/A")
                    finding["cvss_avg"]       = nvd_data.get("cvss_avg",       "N/A")
                    finding["sample_cve"]     = nvd_data.get("sample_cve",     "N/A")
                    finding["sample_cve_url"] = nvd_data.get("sample_cve_url", "")

                else:
                    # Unmapped finding type — set safe fallback values
                    finding["cwe_id"]     = "N/A"
                    finding["wstg_ref"]   = "N/A"
                    finding["cve_count"]  = "N/A"
                    finding["cvss_avg"]   = "N/A"

        logger.info("NVD enrichment complete")
        return findings

    def _match_metadata(self, finding_type: str) -> Optional[dict]:
        """
        Find the best matching metadata entry for a finding type.
        Uses substring matching so partial type names still match.
        """
        for key, metadata in FINDING_METADATA.items():
            if key.lower() in finding_type.lower():
                return metadata
        return None

    def _fetch_nvd(self, cwe_id: str) -> dict:
        """
        Query the NVD CVE API 2.0 for CVEs associated with `cwe_id`.

        Returns a dict with cve_count, cvss_avg, sample_cve, sample_cve_url.
        """
        logger.debug(f"Querying NVD API for {cwe_id}")

        try:
            response = self.session.get(
                NVD_API_BASE,
                params={
                    "cweId":          cwe_id,
                    "resultsPerPage": 5,
                },
                timeout=15,
            )

            if response.status_code != 200:
                logger.warning(f"NVD API returned HTTP {response.status_code} for {cwe_id}")
                return {}

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            if not vulnerabilities:
                return {"cve_count": total}

            # Calculate average CVSS score from returned results
            scores = []
            for v in vulnerabilities:
                metrics = v.get("cve", {}).get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31") or
                    metrics.get("cvssMetricV30") or
                    metrics.get("cvssMetricV2") or []
                )
                if cvss_data:
                    score = cvss_data[0].get("cvssData", {}).get("baseScore")
                    if score:
                        scores.append(float(score))

            cvss_avg = round(sum(scores) / len(scores), 1) if scores else "N/A"

            # Pick the most recent CVE as a sample reference
            sample = vulnerabilities[0].get("cve", {})
            sample_id  = sample.get("id", "N/A")
            sample_url = f"https://nvd.nist.gov/vuln/detail/{sample_id}" if sample_id != "N/A" else ""

            logger.debug(f"NVD: {cwe_id} — {total} CVEs, avg CVSS: {cvss_avg}, sample: {sample_id}")

            return {
                "cve_count":      total,
                "cvss_avg":       cvss_avg,
                "sample_cve":     sample_id,
                "sample_cve_url": sample_url,
            }

        except requests.exceptions.Timeout:
            logger.warning(f"NVD API timeout for {cwe_id}")
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed for {cwe_id}: {e}")
        except Exception as e:
            logger.error(f"NVD API parsing error for {cwe_id}: {e}")

        return {}
