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
from urllib.parse import urlparse, parse_qs
from typing import List, Optional
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, MofNCompleteColumn, TimeElapsedColumn,
)
from config import ScannerConfig
from payloads import XSS_PAYLOADS
from utils.logger import get_logger
from utils.file_handler import screenshot_path, ensure_evidence_dir
from utils.http import build_session
from utils.url import inject_param
from utils.console import console

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

        # Pre-compute work items so we can show an accurate progress bar
        # and give a meaningful time estimate before the browser even starts.
        param_urls = [u for u in urls if "?" in u]
        total_items = len(param_urls) + len(self.forms)

        if total_items == 0:
            logger.info("XSS: no URL parameters or forms to probe — skipping")
            return findings

        # Rough estimate: each item involves up to max_payloads_per_param
        # browser navigations at browser_timeout ms each.
        worst_case_s = (
            total_items * self.config.max_payloads_per_param
            * (self.config.browser_timeout / 1000)
        )
        logger.info(
            f"XSS: probing {len(param_urls)} URL(s) and {len(self.forms)} form(s) "
            f"— up to {int(worst_case_s)}s in the worst case "
            f"(reduce with --browser-timeout)"
        )

        # ── Session validity check ─────────────────────────────────────────
        # Verify the auth cookie can reach an authenticated page before
        # spending time on probes. If the session is invalid, all HTTP
        # pre-filter checks will see login.php (no reflection) and every
        # probe will be silently skipped.
        # Log only whether a cookie is present, not its value.
        _SESSION_NAMES = {"phpsessid", "session", "sessionid", "connect.sid"}
        cookie_info = self.config.auth_cookie or "<none>"
        cookie_display = (
            "; ".join(
                f"{p.split('=')[0]}={p.split('=', 1)[1][:6]}***"
                if "=" in p and p.split("=")[0].strip().lower() in _SESSION_NAMES
                else p.strip()
                for p in cookie_info.split(";") if p.strip()
            ) if self.config.auth_cookie else "<none>"
        )
        _log_cookie = (
            logger.warning if "impossible" in cookie_info.lower() else logger.info
        )
        _log_cookie(f"XSS: auth cookie = {cookie_display}")
        if "impossible" in cookie_info.lower():
            logger.warning(
                "XSS: security=impossible detected in cookie — the application is "
                "running at its hardest security level and XSS payloads will be "
                "HTML-encoded server-side. Re-run with --username / --password so "
                "the scanner can set the security level to Low before probing."
            )
        try:
            probe = self.session.get(
                self.config.target.rstrip("/") + "/index.php",
                timeout=self.config.request_timeout,
                allow_redirects=False,
            )
            if probe.status_code in (301, 302, 303, 307, 308):
                logger.warning(
                    f"XSS: session appears invalid — "
                    f"index.php redirected (HTTP {probe.status_code}). "
                    f"All HTTP pre-filter checks will fail. "
                    f"Re-run with --username / --password to obtain a fresh session."
                )
            else:
                logger.info(f"XSS: session validated — index.php returned HTTP {probe.status_code}")
        except Exception as e:
            logger.warning(f"XSS: session probe failed: {e}")

        # Launch a single browser instance shared across all probes.
        # Wrapping in try/except ensures a missing Playwright installation or
        # any browser-level crash degrades gracefully rather than aborting the scan.
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=self.config.headless)
                context = browser.new_context()

                # Inject all auth cookies into browser context.
                # auth_cookie may be "name=value" or "name1=v1; name2=v2".
                if self.config.auth_cookie:
                    cookie_entries = []
                    for part in self.config.auth_cookie.split(";"):
                        part = part.strip()
                        if not part:
                            continue
                        n, _, v = part.partition("=")
                        n = n.strip(); v = v.strip()
                        if n:
                            cookie_entries.append({
                                "name":  n,
                                "value": v,
                                "url":   self.config.target,
                            })
                    if cookie_entries:
                        context.add_cookies(cookie_entries)

                page = context.new_page()

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[cyan]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("XSS — URL params", total=total_items)

                    # Test URL parameters
                    for url in param_urls:
                        short = url if len(url) <= 55 else url[:52] + "..."
                        progress.update(task, description=f"XSS — {short}")
                        findings.extend(self._test_url(url, page))
                        progress.advance(task)

                    # Test form injection vectors
                    for form in self.forms:
                        action = form.get("action", "")
                        short = action if len(action) <= 50 else action[:47] + "..."
                        progress.update(task, description=f"XSS form — {short}")
                        findings.extend(self._test_form(form, page))
                        progress.advance(task)

                browser.close()

        except Exception as e:
            msg = str(e).lower()
            if "executable" in msg or "playwright" in msg or "chromium" in msg:
                logger.error(
                    "Playwright browser executable not found — XSS browser checks skipped. "
                    "Fix with: playwright install chromium"
                )
            else:
                logger.error(
                    f"XSS detector browser session failed: {e} — "
                    "browser-based checks skipped"
                )

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

        An HTTP pre-filter (same approach as _test_url) submits the form via
        requests first. Only if the payload is reflected in the HTTP response
        do we launch the browser to confirm execution. This eliminates the vast
        majority of browser navigations — typically 90%+ on real applications.
        """
        findings = []
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])

        if not action or not inputs:
            return findings

        # Use a short timeout for probe navigations — XSS dialogs fire in
        # under a second if they fire at all. 5 seconds is generous.
        probe_timeout = min(self.config.browser_timeout, 5000)

        for field in inputs:
            payloads = XSS_PAYLOADS[:self.config.max_payloads_per_param]
            for payload in payloads:
                logger.debug(f"XSS form probe [{field}] → {action}")

                # ── HTTP pre-filter ────────────────────────────────────────
                # Submit the form via requests. If the payload is not in the
                # response body, there is nothing for the browser to execute.
                #
                # Use the raw payload for the target field, but for the
                # submit-button field (name == value, e.g. Submit=Submit)
                # keep its original value so DVWA processes the form.
                # Other fields (including user_token) are set to "test".
                data = {}
                for i in inputs:
                    if i == field:
                        data[i] = payload
                    elif i.lower() in ("submit", "login", "btn", "go"):
                        data[i] = i.capitalize()   # keep submit buttons valid
                    else:
                        data[i] = "test"
                try:
                    if method == "post":
                        resp = self.session.post(
                            action, data=data,
                            timeout=self.config.request_timeout,
                            allow_redirects=True,
                        )
                    else:
                        resp = self.session.get(
                            action, params=data,
                            timeout=self.config.request_timeout,
                            allow_redirects=True,
                        )

                    if payload not in resp.text:
                        logger.debug(
                            f"Payload not reflected in HTTP response — "
                            f"skipping browser for [{field}] on {action}"
                        )
                        continue
                except requests.exceptions.RequestException as e:
                    logger.debug(f"HTTP pre-filter failed for {action}: {e}")
                    continue
                # ──────────────────────────────────────────────────────────

                logger.debug(
                    f"Payload reflected — confirming in browser [{field}] on {action}"
                )

                dialog_triggered = {"value": False, "message": ""}

                def handle_dialog(dialog: Dialog) -> None:
                    dialog_triggered["value"] = True
                    dialog_triggered["message"] = dialog.message
                    dialog.dismiss()

                page.on("dialog", handle_dialog)

                try:
                    page.goto(
                        action,
                        timeout=probe_timeout,
                        wait_until="domcontentloaded",
                    )

                    # Fill all fields, inject payload into the target field
                    for input_name in inputs:
                        locator = page.locator(f"[name='{input_name}']")
                        if locator.count() > 0:
                            value = payload if input_name == field else "test"
                            try:
                                locator.first.fill(value, timeout=probe_timeout)
                            except Exception as e:
                                logger.debug(
                                    f"Could not fill field '{input_name}' "
                                    f"on {action}: {e}"
                                )

                    # Submit the form
                    submit = page.locator("input[type='submit'], button[type='submit']")
                    if submit.count() > 0:
                        submit.first.click(timeout=probe_timeout)
                        page.wait_for_load_state(
                            "domcontentloaded", timeout=probe_timeout,
                        )

                except Exception as e:
                    logger.warning(f"Form XSS probe failed on {action}: {e}")
                    page.remove_listener("dialog", handle_dialog)
                    continue

                page.remove_listener("dialog", handle_dialog)

                if dialog_triggered["value"]:
                    evidence_path = self._take_screenshot(page, f"xss_form_{field}")
                    logger.warning(f"XSS confirmed via form [{field}] on {action}")
                    # Distinguish stored XSS (payload persisted server-side and
                    # executed on a subsequent page load) from reflected XSS
                    # (payload echoed back immediately in the same response).
                    # Heuristic: if the form action URL contains "xss_s" or
                    # "stored" it is almost certainly a stored XSS endpoint.
                    _action_lower = action.lower()
                    _xss_kind = (
                        "Stored"
                        if ("xss_s" in _action_lower or "stored" in _action_lower)
                        else "Reflected"
                    )
                    findings.append({
                        "type":     f"Cross-Site Scripting — Form ({_xss_kind})",
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

        # XSS dialogs fire almost immediately — cap probe navigation at 5 s.
        probe_timeout = min(self.config.browser_timeout, 5000)

        try:
            page.goto(
                url,
                timeout=probe_timeout,
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
