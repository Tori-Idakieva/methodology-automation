"""
http_crawler.py — HTTP-level crawler using the requests library.

Discovers URLs by fetching pages and parsing anchor tags, without
executing JavaScript. Fast and lightweight; complements the browser crawler.

Also extracts HTML forms and their input fields, which are passed to
detectors as injection vectors for XSS and SQLi testing.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from typing import List, Optional
from config import ScannerConfig
from utils.logger import get_logger

logger = get_logger(__name__)


class HttpCrawler:
    """Crawl a target site using plain HTTP requests."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.visited: set = set()
        self.found_urls: List[str] = []
        self.forms: List[dict] = []         # discovered form injection vectors

        # Build a persistent session — reuses connections and carries headers
        self.session = requests.Session()
        self.session.headers.update(config.default_headers)

        # Inject auth cookie if provided (e.g. "PHPSESSID=abc123")
        if config.auth_cookie:
            name, _, value = config.auth_cookie.partition("=")
            self.session.cookies.set(name.strip(), value.strip())
            logger.debug(f"Auth cookie set: {name.strip()}")

    def crawl(self, url: str = None, depth: int = 0) -> List[str]:
        """
        Recursively crawl from `url` up to config.max_depth.

        Returns a deduplicated list of all discovered URLs.
        """
        if url is None:
            url = self.config.target

        # Stop conditions
        if depth > self.config.max_depth:
            logger.debug(f"Max depth reached at: {url}")
            return self.found_urls

        if len(self.found_urls) >= self.config.max_urls:
            logger.debug("Max URL limit reached, stopping crawl")
            return self.found_urls

        if url in self.visited:
            return self.found_urls

        if not self._in_scope(url):
            logger.debug(f"Out of scope, skipping: {url}")
            return self.found_urls

        # Mark visited and record
        self.visited.add(url)
        self.found_urls.append(url)
        logger.info(f"Crawling [{depth}/{self.config.max_depth}]: {url}")

        # Fetch the page
        response = self._fetch(url)
        if response is None:
            return self.found_urls

        # Extract forms from this page
        page_forms = self._extract_forms(url, response.text)
        if page_forms:
            self.forms.extend(page_forms)
            logger.debug(f"Found {len(page_forms)} form(s) on {url}")

        # Extract links and recurse
        links = self._extract_links(url, response.text)
        logger.debug(f"Found {len(links)} link(s) on {url}")

        for link in links:
            self.crawl(link, depth + 1)

        return self.found_urls

    def _fetch(self, url: str) -> Optional[requests.Response]:
        """
        Perform a GET request and return the response, or None on failure.
        Only follows redirects that stay within scope.
        """
        try:
            response = self.session.get(
                url,
                timeout=self.config.request_timeout,
                allow_redirects=True,
            )
            # If redirected out of scope, discard
            if not self._in_scope(response.url):
                logger.warning(f"Redirect out of scope: {url} → {response.url}")
                return None

            logger.debug(f"HTTP {response.status_code} — {url}")
            return response

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching: {url}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error fetching: {url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")

        return None

    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """
        Parse anchor hrefs from HTML, resolve against base_url,
        normalise, and return only in-scope URLs not yet visited.
        """
        soup = BeautifulSoup(html, "html.parser")
        links = []

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()

            # Skip non-navigable hrefs
            if href.startswith(("mailto:", "javascript:", "tel:", "#")):
                continue

            normalised = self._normalise_url(base_url, href)

            if normalised and normalised not in self.visited and self._in_scope(normalised):
                links.append(normalised)

        return links

    def _extract_forms(self, base_url: str, html: str) -> List[dict]:
        """
        Extract all HTML forms from the page.

        Returns a list of dicts with keys:
          - url:     the page the form was found on
          - action:  resolved form submission URL
          - method:  "get" or "post"
          - inputs:  list of input field names
        """
        soup = BeautifulSoup(html, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            action = self._normalise_url(base_url, form.get("action") or base_url)
            method = form.get("method", "get").lower()
            inputs = [
                i.get("name")
                for i in form.find_all(["input", "textarea", "select"])
                if i.get("name")
            ]
            forms.append({
                "url":    base_url,
                "action": action,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def _normalise_url(self, base_url: str, href: str) -> Optional[str]:
        """
        Resolve `href` against `base_url` and strip URL fragments.

        Returns the normalised absolute URL, or None if the scheme is invalid.
        """
        try:
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)

            # Only follow http/https URLs
            if parsed.scheme not in ("http", "https"):
                return None

            # Strip fragment (#section) — fragments are client-side only
            clean = parsed._replace(fragment="")
            return urlunparse(clean)

        except Exception as e:
            logger.debug(f"Could not normalise URL '{href}': {e}")
            return None

    def _in_scope(self, url: str) -> bool:
        """Return True if `url` belongs to the same domain as the target."""
        target_netloc = urlparse(self.config.target).netloc
        url_netloc = urlparse(url).netloc
        return url_netloc == target_netloc
