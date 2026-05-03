"""
main.py — Entry point for the OWASP WSTG-aligned security scanner.

Orchestrates the crawl → detect → report pipeline.
"""

from cli import parse_args
from config import ScannerConfig
from http_crawler import HttpCrawler
from browser_crawler import BrowserCrawler
from detectors.xss import XSSDetector
from detectors.sqli import SQLiDetector
from detectors.headers import HeadersDetector
from detectors.dir_listing import DirectoryListingDetector
from reporting.json_report import JSONReporter
from reporting.html_report import HTMLReporter
from reporting.summary import SummaryReporter
from utils.logger import get_logger, configure_from_config

logger = get_logger(__name__)


def main():
    args   = parse_args()
    config = ScannerConfig.from_args(args)
    configure_from_config(log_level=config.log_level, verbose=config.verbose)

    # Guard — both or neither credential flags must be supplied
    if bool(config.username) != bool(config.password):
        logger.critical("--username and --password must be used together")
        raise SystemExit(1)

    logger.info(f"Starting scan against: {config.target}")

    # --- Crawl ---
    http_crawler    = HttpCrawler(config)
    browser_crawler = BrowserCrawler(config)

    http_urls    = http_crawler.crawl()
    browser_urls = browser_crawler.crawl()
    all_urls     = list(set(http_urls + browser_urls))
    all_forms    = http_crawler.forms + browser_crawler.forms

    logger.info(f"Discovered {len(all_urls)} unique URL(s), {len(all_forms)} form(s)")

    # --- Detect ---
    findings = []
    detectors = [
        XSSDetector(config, forms=all_forms),
        SQLiDetector(config, forms=all_forms),
        HeadersDetector(config),
        DirectoryListingDetector(config),
    ]

    for detector in detectors:
        results = detector.run(all_urls)
        findings.extend(results)

    logger.info(f"Scan complete — {len(findings)} finding(s) recorded")

    # --- Report ---
    if config.format in ("json", "both"):
        JSONReporter(config).write(findings)

    if config.format in ("html", "both"):
        HTMLReporter(config).write(findings)

    SummaryReporter(config).print(findings)


if __name__ == "__main__":
    main()
