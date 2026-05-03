"""
browser_crawler.py — Playwright-powered browser crawler.

Discovers URLs by navigating pages in a real browser context, allowing
JavaScript-rendered content and client-side routing to be captured.
Also handles login, form extraction, screenshot capture, and dialog detection.
"""

from playwright.sync_api import sync_playwright, Page, Dialog
from typing import List, Optional
from config import ScannerConfig
from utils.logger import get_logger
from utils.file_handler import screenshot_path, ensure_evidence_dir
from utils.url import normalise_url, in_scope

logger = get_logger(__name__)


class BrowserCrawler:
    """Crawl a target site using a headless Playwright browser."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.visited: set = set()
        self.found_urls: List[str] = []
        self.forms: List[dict] = []         # discovered form injection vectors
        self.dialogs_triggered: List[dict] = []  # captured alert/confirm/prompt events

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, url: str = None) -> List[str]:
        """
        Launch a browser, optionally log in, then crawl from `url`.

        Returns a deduplicated list of all discovered URLs.
        """
        start_url = url or self.config.target

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.config.headless)
            context = browser.new_context()

            # Inject auth cookie into the browser context if provided
            if self.config.auth_cookie:
                name, _, value = self.config.auth_cookie.partition("=")
                context.add_cookies([{
                    "name":  name.strip(),
                    "value": value.strip(),
                    "url":   self.config.target,
                }])
                logger.debug(f"Auth cookie injected: {name.strip()}")

            page = context.new_page()
            self._attach_dialog_handler(page)

            # Attempt login before crawling if credentials supplied
            if self.config.username and self.config.password:
                self._login(page)

            # Begin recursive crawl
            self._crawl_page(page, start_url, depth=0)

            browser.close()

        logger.info(f"Browser crawl complete — {len(self.found_urls)} URL(s) discovered")
        return self.found_urls

    def screenshot(self, page: Page, label: str) -> Optional[str]:
        """
        Capture a screenshot of the current page if screenshots are enabled.

        Args:
            page:  Playwright Page object.
            label: Descriptive name used to build the filename.

        Returns:
            File path of the saved screenshot, or None if disabled.
        """
        if not self.config.screenshots:
            return None

        ensure_evidence_dir()
        path = screenshot_path(label)
        try:
            page.screenshot(path=path, full_page=True)
            logger.debug(f"Screenshot saved: {path}")
            return path
        except Exception as e:
            logger.warning(f"Screenshot failed for '{label}': {e}")
            return None

    # ------------------------------------------------------------------
    # Internal crawl logic
    # ------------------------------------------------------------------

    def _crawl_page(self, page: Page, url: str, depth: int) -> None:
        """Recursively navigate to `url` and extract links and forms."""

        # Stop conditions
        if depth > self.config.max_depth:
            logger.debug(f"Max depth reached at: {url}")
            return

        if len(self.found_urls) >= self.config.max_urls:
            logger.debug("Max URL limit reached, stopping crawl")
            return

        if url in self.visited:
            return

        if not in_scope(url, self.config.target):
            logger.debug(f"Out of scope, skipping: {url}")
            return

        self.visited.add(url)
        self.found_urls.append(url)
        logger.info(f"Browser crawling [{depth}/{self.config.max_depth}]: {url}")

        # Navigate to the page
        if not self._goto(page, url):
            return

        # Capture screenshot of each crawled page if enabled
        self.screenshot(page, f"crawl_{len(self.found_urls)}")

        # Extract forms from the live DOM
        page_forms = self._extract_forms(page, url)
        if page_forms:
            self.forms.extend(page_forms)
            logger.debug(f"Found {len(page_forms)} form(s) on {url}")

        # Extract links and recurse
        links = self._extract_links(page, url)
        logger.debug(f"Found {len(links)} link(s) on {url}")

        for link in links:
            self._crawl_page(page, link, depth + 1)

    def _goto(self, page: Page, url: str) -> bool:
        """
        Navigate to `url` and wait for DOM content to load.

        Returns True on success, False on timeout or navigation error.
        """
        try:
            page.goto(
                url,
                timeout=self.config.browser_timeout,
                wait_until="domcontentloaded",
            )
            logger.debug(f"Navigated to: {url}")
            return True
        except Exception as e:
            logger.warning(f"Navigation failed for {url}: {e}")
            return False

    def _login(self, page: Page) -> None:
        """
        Attempt to log in using config.username and config.password.

        Navigates to the target, looks for a password field, fills in
        credentials and submits. Generic enough to work with DVWA and
        Juice Shop without hardcoding field names.
        """
        logger.info(f"Attempting login as '{self.config.username}'")

        if not self._goto(page, self.config.target):
            logger.error("Could not reach target for login")
            return

        try:
            # Look for a password input — if not found, we may already be logged in
            password_field = page.query_selector("input[type='password']")
            if not password_field:
                logger.info("No login form found — may already be authenticated")
                return

            # Fill username — try common field names
            for selector in ["input[name='username']", "input[name='user']",
                             "input[name='email']", "input[type='text']"]:
                field = page.query_selector(selector)
                if field:
                    field.fill(self.config.username)
                    logger.debug(f"Filled username using selector: {selector}")
                    break

            # Fill password
            password_field.fill(self.config.password)
            logger.debug("Filled password field")

            # Submit — look for a submit button or just press Enter
            submit = page.query_selector("input[type='submit'], button[type='submit']")
            if submit:
                submit.click()
            else:
                password_field.press("Enter")

            page.wait_for_load_state("domcontentloaded",
                                     timeout=self.config.browser_timeout)
            logger.info("Login submitted successfully")

        except Exception as e:
            logger.error(f"Login attempt failed: {e}")

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """
        Query all anchor hrefs from the live DOM, resolve and normalise them.

        Returns only in-scope URLs not yet visited.
        """
        try:
            # Run JS in the browser to collect all absolute href values
            hrefs = page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                          .map(a => a.href)
            """)
        except Exception as e:
            logger.warning(f"Link extraction failed on {base_url}: {e}")
            return []

        links = []
        for href in hrefs:
            normalised = normalise_url(base_url, href)
            if normalised and normalised not in self.visited and in_scope(normalised, self.config.target):
                links.append(normalised)

        return links

    def _extract_forms(self, page: Page, base_url: str) -> List[dict]:
        """
        Extract all HTML forms from the live DOM via JavaScript.

        Returns a list of dicts with:
          - url:    the page the form was found on
          - action: resolved form submission URL
          - method: "get" or "post"
          - inputs: list of named input field names
        """
        try:
            raw_forms = page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action || '',
                    method: (form.method || 'get').toLowerCase(),
                    inputs: Array.from(
                        form.querySelectorAll('input, textarea, select')
                    ).filter(i => i.name).map(i => i.name)
                }))
            """)
        except Exception as e:
            logger.warning(f"Form extraction failed on {base_url}: {e}")
            return []

        forms = []
        for f in raw_forms:
            action = normalise_url(base_url, f["action"]) or base_url
            forms.append({
                "url":    base_url,
                "action": action,
                "method": f["method"],
                "inputs": f["inputs"],
            })

        return forms

    # ------------------------------------------------------------------
    # Dialog handler
    # ------------------------------------------------------------------

    def _attach_dialog_handler(self, page: Page) -> None:
        """
        Listen for browser dialogs (alert, confirm, prompt).

        During crawling, dialogs are auto-dismissed. The event is recorded
        in self.dialogs_triggered so XSS detectors can use it as evidence.
        """
        def handle_dialog(dialog: Dialog) -> None:
            logger.warning(
                f"Dialog triggered — type: {dialog.type}, message: {dialog.message}"
            )
            self.dialogs_triggered.append({
                "type":    dialog.type,
                "message": dialog.message,
                "url":     page.url,
            })
            dialog.dismiss()

        page.on("dialog", handle_dialog)

