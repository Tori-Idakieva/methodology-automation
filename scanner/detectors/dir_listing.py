"""
detectors/dir_listing.py — Directory listing exposure detector.

OWASP WSTG reference: WSTG-CONF-04

Strategy:
  1. Extract unique origins from crawled URLs.
  2. Probe each origin against a list of common directory paths.
  3. Check HTTP responses for directory listing signatures in the body.
  4. Also check for any directories discovered during crawling.
  5. Flag exposed directories as Medium severity findings.
"""

import requests
from urllib.parse import urlparse, urljoin
from typing import List, Optional
from config import ScannerConfig
from payloads import DIR_LISTING_SIGNATURES
from utils.logger import get_logger
from utils.http import build_session

logger = get_logger(__name__)

# Common directories worth probing
COMMON_DIRS = [
    "/",
    "/admin/",
    "/backup/",
    "/config/",
    "/files/",
    "/images/",
    "/includes/",
    "/logs/",
    "/tmp/",
    "/uploads/",
    "/static/",
    "/assets/",
    "/data/",
]


class DirectoryListingDetector:
    """Detect web server directory listing exposure."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = build_session(config)

    def run(self, urls: List[str]) -> List[dict]:
        """
        Probe directories derived from discovered URLs.

        Tests COMMON_DIRS against each unique origin, plus any directory
        paths found during crawling that haven't already been probed.

        Returns a list of finding dicts.
        """
        findings = []
        probed = set()

        # Extract unique origins from crawled URLs
        origins = self._extract_origins(urls)
        logger.info(f"Probing directory listing on {len(origins)} origin(s)")

        for origin in origins:
            # Probe every common directory path
            for directory in COMMON_DIRS:
                target_url = origin.rstrip("/") + directory
                if target_url in probed:
                    continue
                probed.add(target_url)

                finding = self._probe_directory(target_url)
                if finding:
                    findings.append(finding)

            # Also probe any crawled paths that look like directories
            crawled_dirs = self._extract_crawled_dirs(urls, origin)
            for dir_url in crawled_dirs:
                if dir_url in probed:
                    continue
                probed.add(dir_url)

                finding = self._probe_directory(dir_url)
                if finding:
                    findings.append(finding)

        return findings

    def _probe_directory(self, url: str) -> Optional[dict]:
        """
        GET the directory URL and check the response body for listing signatures.

        Returns a finding dict if directory listing is detected, else None.
        """
        try:
            response = self.session.get(
                url,
                timeout=self.config.request_timeout,
                allow_redirects=True,
            )

            # Only check successful responses
            if response.status_code not in (200, 203):
                logger.debug(f"HTTP {response.status_code} — {url} (skipping)")
                return None

            body = response.text.lower()

            for signature in DIR_LISTING_SIGNATURES:
                if signature in body:
                    logger.warning(f"Directory listing exposed: {url} (matched: '{signature}')")
                    return {
                        "type":     "Directory Listing Exposed",
                        "url":      url,
                        "severity": "Medium",
                        "detail":   (
                            f"The server returned a directory listing for '{url}'. "
                            f"This can expose sensitive files and folder structure."
                        ),
                        "evidence": f"Response body contained signature: '{signature}'",
                    }

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout probing: {url}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error probing: {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")

        return None

    def _extract_origins(self, urls: List[str]) -> List[str]:
        """
        Return a deduplicated list of scheme + host origins from `urls`.

        e.g. ['http://localhost:42001']
        """
        origins = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                origins.add(f"{parsed.scheme}://{parsed.netloc}")
        return list(origins)

    def _extract_crawled_dirs(self, urls: List[str], origin: str) -> List[str]:
        """
        From the list of crawled URLs, extract paths that look like directories
        (i.e. end with /) and belong to `origin`.

        This catches directories the crawler discovered that aren't in COMMON_DIRS.
        """
        dirs = set()
        for url in urls:
            if not url.startswith(origin):
                continue
            parsed = urlparse(url)
            path = parsed.path
            # If the path ends with / it is itself a directory
            if path.endswith("/") and path != "/":
                dirs.add(origin + path)
            # Also probe the parent directory of any file path
            elif "/" in path:
                parent = path.rsplit("/", 1)[0] + "/"
                if parent != "/":
                    dirs.add(origin + parent)
        return list(dirs)
