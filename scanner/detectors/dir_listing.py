"""
detectors/dir_listing.py — Directory listing exposure detector.

OWASP WSTG reference: WSTG-CONF-04

Strategy:
  1. Probe common directory paths on the target.
  2. Check HTTP responses for directory listing signatures.
  3. Flag exposed directories as Medium severity findings.
"""

from typing import List
from config import ScannerConfig
from payloads import DIR_LISTING_SIGNATURES
from utils.logger import get_logger

logger = get_logger(__name__)

# Common directories worth probing
COMMON_DIRS = [
    "/",
    "/admin/",
    "/backup/",
    "/config/",
    "/files/",
    "/images/",
    "/logs/",
    "/tmp/",
    "/uploads/",
]


class DirectoryListingDetector:
    """Detect web server directory listing exposure."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def run(self, urls: List[str]) -> List[dict]:
        """
        Probe directories derived from discovered URLs.

        Returns a list of finding dicts.
        """
        # TODO:
        #   - extract unique base origins from urls
        #   - for each origin × COMMON_DIRS: call _probe_directory()
        raise NotImplementedError

    def _probe_directory(self, url: str) -> dict | None:
        """
        GET the directory URL and check response body for listing signatures.

        Returns a finding dict if directory listing is detected, else None.
        """
        # TODO:
        #   - requests.get(url)
        #   - if any sig in response.text.lower() → return finding
        raise NotImplementedError
