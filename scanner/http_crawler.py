"""
http_crawler.py — HTTP-level crawler using the requests library.

Discovers URLs by fetching pages and parsing anchor tags, without
executing JavaScript. Fast and lightweight; complements the browser crawler.
"""

from typing import List
from config import ScannerConfig
from utils.logger import get_logger

logger = get_logger(__name__)


class HttpCrawler:
    """Crawl a target site using plain HTTP requests."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.visited: set = set()
        self.found_urls: List[str] = []

    def crawl(self, url: str = None, depth: int = 0) -> List[str]:
        """
        Recursively crawl from `url` up to config.max_depth.

        Returns a list of discovered URLs.
        """
        # TODO: implement requests + BeautifulSoup link extraction
        raise NotImplementedError

    def _fetch(self, url: str):
        """Perform a GET request and return the response, or None on failure."""
        # TODO: use requests.Session with config.default_headers and timeout
        raise NotImplementedError

    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """Parse anchor hrefs from HTML and resolve them against base_url."""
        # TODO: BeautifulSoup find_all("a", href=True) + urllib.parse.urljoin
        raise NotImplementedError
