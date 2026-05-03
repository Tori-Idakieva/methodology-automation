"""
browser_crawler.py — Playwright-powered browser crawler.

Discovers URLs by navigating pages in a real browser context, allowing
JavaScript-rendered content and client-side routing to be captured.
Also responsible for capturing screenshots/DOM snapshots as evidence.
"""

from typing import List
from config import ScannerConfig
from utils.logger import get_logger

logger = get_logger(__name__)


class BrowserCrawler:
    """Crawl a target site using a headless Playwright browser."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.visited: set = set()
        self.found_urls: List[str] = []

    def crawl(self, url: str = None, depth: int = 0) -> List[str]:
        """
        Navigate pages with Playwright and collect discovered URLs.

        Returns a list of discovered URLs.
        """
        # TODO: launch playwright chromium, navigate, extract hrefs from DOM
        raise NotImplementedError

    def screenshot(self, page, label: str) -> str:
        """
        Capture a screenshot of the current browser page.

        Args:
            page: Playwright Page object.
            label: Descriptive name used in the filename.

        Returns:
            File path of the saved screenshot.
        """
        # TODO: page.screenshot(path=f"evidence/{label}.png")
        raise NotImplementedError

    def _extract_links(self, page) -> List[str]:
        """Extract all href values from the current page DOM."""
        # TODO: page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        raise NotImplementedError

    def close(self):
        """Shut down the browser context cleanly."""
        # TODO: browser.close() / playwright.stop()
        raise NotImplementedError
