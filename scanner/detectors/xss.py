"""
detectors/xss.py — Cross-Site Scripting (XSS) detector.

OWASP WSTG reference: WSTG-INPV-01

Strategy:
  1. Inject XSS payloads into URL query parameters and discovered form fields.
  2. HTTP reflection check — if the payload appears verbatim in the response
     body, it is a candidate for execution.
  3. Browser confirmation — navigate to the injected URL in Playwright and
     listen for alert() dialogs. A triggered dialog confirms execution.
  4. Capture a screenshot as evidence when a dialog is triggered.
  5. Also check for DOM injection by inspecting the page source after load.
"""

import requests
from playwright.sync_api import sync_playwright, Page, Dialog
from typing import List, Optional
from config import ScannerConfig
from payloads import XSS_PAYLOADS
from utils.logger import get_logger
from utils.file_handler import screenshot_path, ensure_evidence_dir
from utils.http import build_session
from utils.url import inject_param

logger = get_logger(__name__)


class XSSDetector:
    """Detect reflected and DOM-based XSS vulnerabilities."""

    def __init__(self, config: ScannerConfig, forms: Optional[List[dict]] = None):
        self.config = config
        self.forms = forms or []
        self.session = build_session(config)

    def run(self, urls: List[str]) -> List[dict]:
        """
        Run XSS probes against URL parameters and discovered forms.

        Returns a list of finding dicts.
        """
        findings = []

        # Launch a single browser instance shared across all probes
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.config.headless)
            context = browser.new_context()

            # Inject auth cookie into browser context if provided
            if self.config.auth_cookie:
                name, _, value = self.config.auth_cookie.partition("=")
                context.add_cookies([{
                    "name":  name.strip(),
                    "value": value.strip(),
                    "url":   self.config.target,
                }])

            page = context.new_page()

            # Test URL parameters
            for url in urls:
                if "?" in url:
                    findings.extend(self._test_url(url, page))

            # Test form injection vectors
            for form in self.forms:
                findings.extend(self._test_form(form, page))

            browser.close()

        return findings

    # ------------------------------------------------------------------
    # URL parameter testing
    # ------------------------------------------------------------------

    def _test_url(self, url: str, page: Page) -> List[dict]:
        """
        Inject XSS payloads into each query parameter of `url` one at a time.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        for param in params:
            payloads = XSS_PAYLOADS[:self.config.max_payloads_per_param]
            for payload in payloads:
                injected_url = inject_param(url, param, payload)
                logger.debug(f"XSS probe [{param}]: {injected_url}")

                # Step 1 — quick HTTP reflection check
                if not self._http_probe(injected_url, payload):
                    continue  # payload not reflected, skip browser confirmation

                logger.debug(f"Payload reflected in HTTP response — confirming in browser")

                # Step 2 — browser confirmation
                finding = self._browser_probe(injected_url, param, payload, page)
                if finding:
                    findings.append(finding)
                    break  # confirmed on this param, move to next

        return findings

    # ------------------------------------------------------------------
    # Form testing
    # ------------------------------------------------------------------

    def _test_form(self, form: dict, page: Page) -> List[dict]:
        """
        Inject XSS payloads into each input field of a discovered form.
        Uses Playwright to submit forms and detect dialog execution.
        """
        findings = []
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])

        if not action or not inputs:
            return findings

        for field in inputs:
            payloads = XSS_PAYLOADS[:self.config.max_payloads_per_param]
            for payload in payloads:
                logger.debug(f"XSS form probe [{field}] → {action}")

                dialog_triggered = {"value": False, "message": ""}

                def handle_dialog(dialog: Dialog) -> None:
                    dialog_triggered["value"] = True
                    dialog_triggered["message"] = dialog.message
                    dialog.dismiss()

                page.on("dialog", handle_dialog)

                try:
                    page.goto(
                        action,
                        timeout=self.config.browser_timeout,
                        wait_until="domcontentloaded",
                    )

                    # Fill all fields, inject payload into target field
                    for input_name in inputs:
                        locator = page.locator(f"[name='{input_name}']")
                        if locator.count() > 0:
                            value = payload if input_name == field else "test"
                            try:
                                locator.first.fill(value)
                            except Exception:
                                pass

                    # Submit the form
                    submit = page.locator("input[type='submit'], button[type='submit']")
                    if submit.count() > 0:
                        submit.first.click()
                        page.wait_for_load_state(
                            "domcontentloaded",
                            timeout=self.config.browser_timeout
                        )

                except Exception as e:
                    logger.warning(f"Form XSS probe failed on {action}: {e}")
                    page.remove_listener("dialog", handle_dialog)
                    continue

                page.remove_listener("dialog", handle_dialog)

                if dialog_triggered["value"]:
                    evidence_path = self._take_screenshot(page, f"xss_form_{field}")
                    logger.warning(f"XSS confirmed via form [{field}] on {action}")
                    findings.append({
                        "type":     "Cross-Site Scripting — Form (Reflected)",
                        "url":      action,
                        "severity": "High",
                        "detail":   (
                            f"Field '{field}' executed injected JavaScript. "
                            f"Alert dialog message: '{dialog_triggered['message']}'"
                        ),
                        "evidence": (
                            f"Payload: {payload}"
                            + (f" | Screenshot: {evidence_path}" if evidence_path else "")
                        ),
                    })
                    break

        return findings

    # ------------------------------------------------------------------
    # Probes
    # ------------------------------------------------------------------

    def _http_probe(self, url: str, payload: str) -> bool:
        """
        Fetch `url` and check whether `payload` is reflected verbatim in the
        response body. Used as a fast pre-filter before launching the browser.

        Returns True if reflected, False otherwise.
        """
        try:
            response = self.session.get(
                url,
                timeout=self.config.request_timeout,
                allow_redirects=True,
            )
            return payload in response.text
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP probe failed for {url}: {e}")
            return False

    def _browser_probe(
        self, url: str, param: str, payload: str, page: Page
    ) -> Optional[dict]:
        """
        Navigate to `url` in Playwright and listen for an alert() dialog.

        A triggered dialog confirms that the injected payload was executed
        by the browser — conclusive evidence of reflected XSS.

        Returns a finding dict if confirmed, else None.
        """
        dialog_triggered = {"value": False, "message": ""}

        def handle_dialog(dialog: Dialog) -> None:
            dialog_triggered["value"] = True
            dialog_triggered["message"] = dialog.message
            logger.warning(
                f"XSS alert triggered — param: '{param}', "
                f"message: '{dialog.message}', url: {url}"
            )
            dialog.dismiss()

        page.on("dialog", handle_dialog)

        try:
            page.goto(
                url,
                timeout=self.config.browser_timeout,
                wait_until="domcontentloaded",
            )
        except Exception as e:
            logger.warning(f"Browser probe navigation failed for {url}: {e}")
            page.remove_listener("dialog", handle_dialog)
            return None

        page.remove_listener("dialog", handle_dialog)

        if dialog_triggered["value"]:
            evidence_path = self._take_screenshot(page, f"xss_{param}")
            return {
                "type":     "Cross-Site Scripting — URL Parameter (Reflected)",
                "url":      url,
                "severity": "High",
                "detail":   (
                    f"Parameter '{param}' executed injected JavaScript. "
                    f"Alert dialog message: '{dialog_triggered['message']}'"
                ),
                "evidence": (
                    f"Payload: {payload}"
                    + (f" | Screenshot: {evidence_path}" if evidence_path else "")
                ),
            }

        # Fallback — check if payload is present in rendered DOM source
        # (catches cases where alert is blocked but injection still occurred)
        try:
            dom_content = page.content()
            if payload in dom_content:
                logger.warning(f"XSS payload found in rendered DOM [{param}] on {url}")
                return {
                    "type":     "Cross-Site Scripting — DOM Injection (Unconfirmed)",
                    "url":      url,
                    "severity": "Medium",
                    "detail":   (
                        f"Parameter '{param}' is reflected in the rendered DOM. "
                        f"Alert was not triggered but payload is present — "
                        f"manual verification recommended."
                    ),
                    "evidence": f"Payload: {payload}",
                }
        except Exception as e:
            logger.debug(f"DOM content check failed: {e}")

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _take_screenshot(self, page: Page, label: str) -> Optional[str]:
        """Capture a screenshot if screenshots are enabled. Returns path or None."""
        if not self.config.screenshots:
            return None
        ensure_evidence_dir()
        path = screenshot_path(label)
        try:
            page.screenshot(path=path, full_page=True)
            logger.debug(f"Screenshot saved: {path}")
            return path
        except Exception as e:
            logger.warning(f"Screenshot failed: {e}")
            return None
