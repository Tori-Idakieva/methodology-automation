"""
browser_crawler.py — Playwright-powered browser crawler.

Discovers URLs by navigating pages in a real browser context, allowing
JavaScript-rendered content and client-side routing to be captured.
Also handles login, form extraction, screenshot capture, and dialog detection.
"""

import time
from playwright.sync_api import sync_playwright, Page, Dialog
from typing import List, Optional
from config import ScannerConfig
from utils.logger import get_logger
from utils.file_handler import screenshot_path, ensure_evidence_dir
from utils.url import normalise_url, in_scope

logger = get_logger(__name__)

# URL path segments that would invalidate the current session.
# Any URL whose path contains one of these strings is skipped during crawling.
_LOGOUT_PATTERNS = ("logout", "signout", "sign-out", "log-out", "logoff", "log_off")


class BrowserCrawler:
    """Crawl a target site using a headless Playwright browser."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.visited: set = set()
        self.found_urls: List[str] = []
        self.forms: List[dict] = []         # discovered form injection vectors
        self.dialogs_triggered: List[dict] = []  # captured alert/confirm/prompt events
        self.session_cookie: Optional[str] = None  # captured after login for use by detectors

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, url: str = None) -> List[str]:
        """
        Launch a browser, optionally log in, then crawl from `url`.

        Returns a deduplicated list of all discovered URLs.
        """
        start_url = url or self.config.target

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=self.config.headless)
                context = browser.new_context()

                # Inject auth cookie(s) into the browser context if provided.
                # Handles both single "name=value" and "name1=v1; name2=v2".
                if self.config.auth_cookie:
                    entries = []
                    for part in self.config.auth_cookie.split(";"):
                        part = part.strip()
                        if not part:
                            continue
                        n, _, v = part.partition("=")
                        n = n.strip(); v = v.strip()
                        if n:
                            entries.append({"name": n, "value": v, "url": self.config.target})
                    if entries:
                        context.add_cookies(entries)
                        logger.debug(f"Auth cookie(s) injected: {len(entries)} cookie(s)")

                page = context.new_page()
                self._attach_dialog_handler(page)

                # Attempt login before crawling if credentials supplied
                if self.config.username and self.config.password:
                    self._login(page)
                    # After login the browser has landed on the authenticated
                    # landing page (e.g. index.php). Start crawling from there
                    # rather than re-navigating to the root URL, which would
                    # trigger a redirect back to login.php and lose the context.
                    start_url = page.url or start_url

                    # ── Case 1: login redirected to setup.php ─────────────────
                    # The admin user exists (login worked) but the application
                    # database tables haven't been created yet.
                    if "setup.php" in start_url:
                        logger.warning(
                            "Login redirected to setup.php — "
                            "attempting automatic database initialisation."
                        )
                        self._run_setup(page)
                        self._login(page, _retries=1)
                        start_url = page.url or start_url

                    # ── Case 2: login failed entirely (still on login page) ───
                    # The admin user may not exist yet (database not initialised
                    # at all). Navigate directly to setup.php, create the DB,
                    # then try logging in again.
                    elif "login" in start_url.lower():
                        logger.warning(
                            "Login failed — navigating to setup.php to "
                            "attempt automatic database initialisation."
                        )
                        setup_url = self.config.target.rstrip("/") + "/setup.php"
                        if self._goto(page, setup_url):
                            self._run_setup(page)
                            time.sleep(2)   # give the DB a moment to settle
                        self._login(page, _retries=2)
                        start_url = page.url or start_url

                    if "setup.php" in start_url or "login" in start_url.lower():
                        logger.error(
                            "Database initialisation or login failed. "
                            "Visit /setup.php in your browser and click "
                            "'Create / Reset Database', then re-run the scanner."
                        )

                    # Only attempt to set security level if login succeeded.
                    if "login" not in start_url.lower() and "setup.php" not in start_url:
                        self._set_security_low(page)
                    # Capture ALL relevant cookies so detectors that use a
                    # plain requests.Session can send the exact same cookie
                    # jar as the browser.
                    self.session_cookie = self._capture_cookies(context)

                elif self.config.auth_cookie:
                    # Cookie already injected into context above. Navigate to
                    # the target so _set_security_low can submit the security
                    # form within this authenticated session, then re-capture
                    # the full cookie jar (including any updated security level
                    # cookie) for propagation to detectors.
                    if self._goto(page, self.config.target):
                        self._set_security_low(page)
                    self.session_cookie = self._capture_cookies(context)

                # Begin recursive crawl
                self._crawl_page(page, start_url, depth=0)

                # Re-capture all cookies after crawling — values may have
                # been refreshed during navigation.
                refreshed = self._capture_cookies(context)
                if refreshed:
                    self.session_cookie = refreshed
                    logger.debug("Session cookies refreshed post-crawl")

                browser.close()

        except Exception as e:
            msg = str(e).lower()
            if "executable" in msg or "playwright" in msg or "chromium" in msg:
                logger.error(
                    "Playwright browser executable not found — browser crawl skipped. "
                    "Fix with: playwright install chromium"
                )
            else:
                logger.error(
                    f"Browser crawl failed: {e} — "
                    "continuing with HTTP-only results"
                )

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

        # Skip any URL that would log the browser out and invalidate the session
        from urllib.parse import urlparse as _urlparse
        _path = _urlparse(url).path.lower()
        if any(pat in _path for pat in _LOGOUT_PATTERNS):
            logger.debug(f"Skipping logout URL to preserve session: {url}")
            self.visited.add(url)  # mark visited so we don't re-evaluate
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

    def _login(self, page: Page, _retries: int = 3, _retry_delay: int = 5) -> None:
        """
        Attempt to log in using config.username and config.password.

        Navigates to the target, looks for a password field, fills in
        credentials and submits. Retries up to _retries times with a short
        delay to handle cases where the database is still initialising when
        the scan starts (common on fresh Docker setups).
        """
        for attempt in range(1, _retries + 1):
            logger.info(
                f"Attempting login as '{self.config.username}'"
                + (f" (attempt {attempt}/{_retries})" if attempt > 1 else "")
            )

            if not self._goto(page, self.config.target):
                logger.error("Could not reach target for login")
                return

            try:
                # Look for a password input — if not found, we may already be logged in
                password_field = page.query_selector("input[type='password']")
                if not password_field:
                    logger.info("No login form found — may already be authenticated")
                    return

                # Fill username — try common field names in order
                for selector in ["input[name='username']", "input[name='user']",
                                 "input[name='email']", "input[type='text']"]:
                    field = page.query_selector(selector)
                    if field:
                        field.fill(self.config.username, timeout=self.config.browser_timeout)
                        logger.debug(f"Filled username using selector: {selector}")
                        break

                # Fill password
                password_field.fill(self.config.password, timeout=self.config.browser_timeout)
                logger.debug("Filled password field")

                # Submit — look for a submit button or fall back to pressing Enter
                submit = page.query_selector("input[type='submit'], button[type='submit']")
                if submit:
                    submit.click(timeout=self.config.browser_timeout)
                else:
                    password_field.press("Enter")

                page.wait_for_load_state("domcontentloaded",
                                         timeout=self.config.browser_timeout)

                # Verify we actually landed on an authenticated page.
                landed = page.url
                if "login" not in landed.lower():
                    logger.info(f"Login successful — landed on: {landed}")
                    return   # success

                # Still on login — surface the error message from the page.
                err_msg = ""
                for err_sel in [".loginError", "#error_box", ".error",
                                 "p.message", ".message"]:
                    el = page.query_selector(err_sel)
                    if el:
                        err_msg = el.inner_text().strip()
                        break

                if attempt < _retries:
                    logger.warning(
                        f"Login attempt {attempt} failed"
                        + (f" — '{err_msg}'" if err_msg else "")
                        + f". Retrying in {_retry_delay}s "
                        "(database may still be initialising)..."
                    )
                    time.sleep(_retry_delay)
                else:
                    logger.error(
                        f"Login failed after {_retries} attempt(s) — "
                        f"still on login page ({landed}). "
                        + (f"Server message: '{err_msg}'. " if err_msg else "")
                        + "Check --username / --password are correct and the "
                        "application database is initialised."
                    )

            except Exception as e:
                logger.error(f"Login attempt {attempt} raised an exception: {e}")
                if attempt < _retries:
                    time.sleep(_retry_delay)

    def _run_setup(self, page: Page) -> None:
        """
        If the current page is a setup/initialisation page, click the primary
        submit button to create the database.

        This is a best-effort, generic step. It works for DVWA's setup.php but
        degrades gracefully for any other target — if no submit button is found
        the method returns without error and the scan continues.
        """
        try:
            submit = page.locator("input[type='submit'], button[type='submit']")
            if submit.count() == 0:
                logger.debug("_run_setup: no submit button found on setup page")
                return
            logger.info("Running setup — clicking database initialisation button...")
            submit.first.click(timeout=self.config.browser_timeout)
            page.wait_for_load_state("domcontentloaded", timeout=self.config.browser_timeout)
            logger.info(f"Setup complete — now on: {page.url}")
        except Exception as e:
            logger.warning(f"Setup step failed: {e}")

    def _set_security_low(self, page: Page) -> None:
        """
        Attempt to set the DVWA security level to Low within the current
        browser session by submitting the security.php form.

        This is a best-effort, DVWA-specific step. If security.php does not
        exist on the target the navigation will fail gracefully and the scan
        continues unchanged.
        """
        security_url = self.config.target.rstrip("/") + "/security.php"
        try:
            page.goto(
                security_url,
                timeout=self.config.browser_timeout,
                wait_until="domcontentloaded",
            )
            landed_url = page.url
            logger.debug(f"Security page navigation landed on: {landed_url}")

            # Only act if the security form is actually present.
            # If the browser was redirected (e.g. to login.php because the
            # session is invalid), the form won't exist and we log a warning.
            select = page.locator("select[name='security']")
            if select.count() == 0:
                if "login" in landed_url.lower() or "security.php" not in landed_url.lower():
                    logger.warning(
                        f"Security level form not found — browser was redirected to "
                        f"{landed_url}. The session may be expired or invalid. "
                        f"Re-run with --username / --password to obtain a fresh session."
                    )
                else:
                    logger.debug(
                        "Security level form not found on target — "
                        "target may not support security level selection."
                    )
                return
            select.select_option("low")
            submit = page.locator("input[name='seclev_submit']")
            if submit.count() > 0:
                submit.first.click(timeout=self.config.browser_timeout)
                page.wait_for_load_state(
                    "domcontentloaded", timeout=self.config.browser_timeout
                )
            logger.info("Security level set to Low for this session")
        except Exception as e:
            logger.debug(f"Could not set security level: {e}")

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

    # ------------------------------------------------------------------
    # Cookie helpers
    # ------------------------------------------------------------------

    def _capture_cookies(self, context) -> Optional[str]:
        """
        Collect ALL relevant cookies from the browser context and return
        them as a semicolon-separated 'name=value' string suitable for
        use in a requests.Session or Playwright cookie injection.

        Captures PHPSESSID (authentication) AND the 'security' cookie
        (DVWA uses $_COOKIE['security'] to determine the vulnerability
        level — missing this cookie causes DVWA to default to 'impossible'
        which HTML-encodes all output, silently defeating XSS probes).
        """
        # Names we always want to carry over
        _SESSION_NAMES = {"phpsessid", "session", "sessionid", "connect.sid"}
        _EXTRA_NAMES   = {"security"}   # DVWA-specific level cookie

        parts = []
        try:
            for cookie in context.cookies():
                name_lower = cookie["name"].lower()
                if name_lower in _SESSION_NAMES or name_lower in _EXTRA_NAMES:
                    parts.append(f"{cookie['name']}={cookie['value']}")
                    logger.debug(f"Cookie captured: {cookie['name']}")
        except Exception as e:
            logger.debug(f"Cookie capture failed: {e}")

        result = "; ".join(parts) if parts else None
        if result:
            # Mask session token values (they're auth credentials) but leave
            # non-sensitive config cookies (e.g. security=low) readable.
            masked = "; ".join(
                f"{p.split('=')[0]}={p.split('=', 1)[1][:6]}***"
                if "=" in p and p.split("=")[0].lower() in _SESSION_NAMES
                else p
                for p in parts
            )
            logger.info(f"Cookies propagated to detectors: {masked}")
        return result

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

