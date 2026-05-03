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
from reporting.summary import SummaryReporter
from utils.logger import get_logger

logger = get_logger(__name__)


def main():
    args = parse_args()
    config = ScannerConfig(target=args.target, output=args.output)

    logger.info(f"Starting scan against: {config.target}")

    # --- Crawl ---
    http_crawler = HttpCrawler(config)
    browser_crawler = BrowserCrawler(config)

    http_urls = http_crawler.crawl()
    browser_urls = browser_crawler.crawl()
    all_urls = list(set(http_urls + browser_urls))

    logger.info(f"Discovered {len(all_urls)} unique URLs")

    # --- Detect ---
    findings = []
    detectors = [
        XSSDetector(config),
        SQLiDetector(config),
        HeadersDetector(config),
        DirectoryListingDetector(config),
    ]

    for detector in detectors:
        results = detector.run(all_urls)
        findings.extend(results)

    logger.info(f"Scan complete — {len(findings)} finding(s) recorded")

    # --- Report ---
    JSONReporter(config).write(findings)
    SummaryReporter(config).print(findings)


if __name__ == "__main__":
    main()
