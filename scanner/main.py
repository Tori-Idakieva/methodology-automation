"""
main.py — Entry point for the OWASP WSTG-aligned security scanner.

Orchestrates the crawl → detect → integrate → enrich → report pipeline
and provides live terminal feedback at each phase via Rich.
"""

import requests
from urllib.parse import urlparse

from cli import parse_args
from config import ScannerConfig
from http_crawler import HttpCrawler
from browser_crawler import BrowserCrawler
from detectors.xss import XSSDetector
from detectors.sqli import SQLiDetector
from detectors.headers import HeadersDetector
from detectors.dir_listing import DirectoryListingDetector
from integrations.nvd_api import NVDEnricher
from integrations.sqlmap_runner import SqlmapRunner
from integrations.nikto_runner import NiktoRunner
from reporting.json_report import JSONReporter
from reporting.html_report import HTMLReporter
from reporting.summary import SummaryReporter
from utils.logger import get_logger, configure_from_config
from utils.http import build_session
from utils.file_handler import open_file
from utils.console import console

logger = get_logger(__name__)


# -------------------------------------------------------------------------
# Pre-scan helpers
# -------------------------------------------------------------------------

def _validate_target(config: ScannerConfig) -> None:
    """
    Validate and normalise config.target in-place.

    - Auto-prepends http:// if no scheme is present.
    - Exits with a clear error if the scheme is not http or https.
    - Exits with a clear error if no hostname can be parsed.

    Runs before any network activity so the user gets immediate feedback
    on a bad --target value rather than a cryptic failure mid-scan.
    """
    target = config.target

    # Auto-prepend scheme when the user omits it (e.g. "localhost:8080")
    if "://" not in target:
        target = f"http://{target}"
        logger.warning(
            f"No URL scheme provided — assuming http. "
            f"Pass the full URL to suppress this: http://{config.target}"
        )

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        logger.critical(
            f"Unsupported scheme '{parsed.scheme}' in target '{target}'. "
            "Only http:// and https:// are supported."
        )
        raise SystemExit(1)

    if not parsed.netloc:
        logger.critical(
            f"Invalid target URL '{target}' — could not parse a hostname. "
            "Expected format: http://hostname:port"
        )
        raise SystemExit(1)

    config.target = target   # update in-place — dataclasses are mutable by default


def _preflight_check(config: ScannerConfig) -> None:
    """
    Make a single GET request to the target before the full scan begins.

    Exits immediately with an actionable message if the target is
    unreachable, avoiding a slow or confusing failure mid-scan.
    """
    logger.info(f"Verifying target is reachable: {config.target}")

    try:
        session = build_session(config)
        response = session.get(config.target, timeout=config.request_timeout)
        logger.info(f"Target reachable — HTTP {response.status_code}")

    except requests.exceptions.ConnectionError:
        logger.critical(
            f"Connection refused: {config.target}\n"
            "  • Confirm the target server is running\n"
            "  • Verify the host and port are correct\n"
            "  • If the target is in Docker, ensure the container is up"
        )
        raise SystemExit(1)

    except requests.exceptions.Timeout:
        logger.critical(
            f"Target did not respond within {config.request_timeout}s: {config.target}\n"
            "  • The server may be overloaded or behind a firewall\n"
            "  • Check network connectivity to the target"
        )
        raise SystemExit(1)

    except requests.exceptions.SSLError as e:
        logger.critical(
            f"SSL/TLS error connecting to {config.target}: {e}\n"
            "  • Ensure the certificate is valid, or use http:// for local targets"
        )
        raise SystemExit(1)

    except requests.exceptions.RequestException as e:
        logger.critical(f"Preflight check failed for {config.target}: {e}")
        raise SystemExit(1)


# -------------------------------------------------------------------------
# Terminal helpers
# -------------------------------------------------------------------------

def _phase(title: str) -> None:
    """Print a visual rule dividing scan phases in the terminal output."""
    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]", style="cyan")


# -------------------------------------------------------------------------
# Main pipeline
# -------------------------------------------------------------------------

def main() -> None:
    config = None

    try:
        args   = parse_args()
        config = ScannerConfig.from_args(args)
        configure_from_config(log_level=config.log_level, verbose=config.verbose)

        # Guard — both or neither credential flags must be supplied
        if bool(config.username) != bool(config.password):
            logger.critical("--username and --password must be used together")
            raise SystemExit(1)

        # ----------------------------------------------------------------
        # Pre-scan validation
        # ----------------------------------------------------------------
        _validate_target(config)
        _preflight_check(config)

        # ----------------------------------------------------------------
        # Header banner
        # ----------------------------------------------------------------
        console.print()
        console.rule("[bold white]OWASP WSTG Security Scanner[/bold white]")
        console.print(
            f"[dim]Target:[/dim] [bold]{config.target}[/bold]   "
            f"[dim]Format:[/dim] {config.format}   "
            f"[dim]Depth:[/dim] {config.max_depth}"
        )

        # ----------------------------------------------------------------
        # Phase 1 — Crawl
        # ----------------------------------------------------------------
        _phase("Phase 1 — Crawl")

        http_crawler    = HttpCrawler(config)
        browser_crawler = BrowserCrawler(config)

        with console.status("[cyan]HTTP crawl in progress...[/cyan]"):
            http_urls = http_crawler.crawl()
        console.print(
            f"[green]✓[/green] HTTP crawl complete — "
            f"[bold]{len(http_urls)}[/bold] URL(s)"
        )

        with console.status("[cyan]Browser crawl in progress...[/cyan]"):
            browser_urls = browser_crawler.crawl()
        console.print(
            f"[green]✓[/green] Browser crawl complete — "
            f"[bold]{len(browser_urls)}[/bold] URL(s)"
        )

        all_urls  = list(set(http_urls + browser_urls))
        all_forms = http_crawler.forms + browser_crawler.forms
        console.print(
            f"[dim]Merged:[/dim] [bold]{len(all_urls)}[/bold] unique URL(s), "
            f"[bold]{len(all_forms)}[/bold] form(s)"
        )

        # ----------------------------------------------------------------
        # Phase 2 — Detect
        # ----------------------------------------------------------------
        _phase("Phase 2 — Detect")

        findings = []
        detectors = [
            XSSDetector(config, forms=all_forms),
            SQLiDetector(config, forms=all_forms),
            HeadersDetector(config),
            DirectoryListingDetector(config),
        ]

        for detector in detectors:
            name = type(detector).__name__.replace("Detector", "")
            with console.status(f"[cyan]Running {name} checks...[/cyan]"):
                results = detector.run(all_urls)
                findings.extend(results)
            console.print(
                f"[green]✓[/green] {name}: [bold]{len(results)}[/bold] finding(s)"
            )

        # ----------------------------------------------------------------
        # Phase 3 — External tool integrations (optional)
        # ----------------------------------------------------------------
        if config.use_sqlmap or config.use_nikto:
            _phase("Phase 3 — External Tools")

        if config.use_sqlmap:
            with console.status("[cyan]Running sqlmap...[/cyan]"):
                sqlmap_findings = SqlmapRunner(
                    target=config.target,
                    urls=all_urls,
                    forms=all_forms,
                ).run()
            findings.extend(sqlmap_findings)
            console.print(
                f"[green]✓[/green] sqlmap: "
                f"[bold]{len(sqlmap_findings)}[/bold] finding(s)"
            )

        if config.use_nikto:
            with console.status("[cyan]Running Nikto...[/cyan]"):
                nikto_findings = NiktoRunner(target=config.target).run()
            findings.extend(nikto_findings)
            console.print(
                f"[green]✓[/green] Nikto: "
                f"[bold]{len(nikto_findings)}[/bold] finding(s)"
            )

        console.print(
            f"\n[dim]Total findings before enrichment:[/dim] "
            f"[bold]{len(findings)}[/bold]"
        )

        # ----------------------------------------------------------------
        # Phase 4 — NVD CVE enrichment
        # ----------------------------------------------------------------
        _phase("Phase 4 — NVD Enrichment")

        findings = NVDEnricher().enrich(findings)

        # ----------------------------------------------------------------
        # Phase 5 — Report
        # ----------------------------------------------------------------
        _phase("Phase 5 — Report")

        written_paths = []

        if config.format in ("json", "both"):
            path = JSONReporter(config).write(findings)
            written_paths.append(path)
            console.print(f"[green]✓[/green] JSON report → [bold]{path}[/bold]")

        if config.format in ("html", "both"):
            path = HTMLReporter(config).write(findings)
            written_paths.append(path)
            console.print(f"[green]✓[/green] HTML report → [bold]{path}[/bold]")

        # ----------------------------------------------------------------
        # Terminal summary table
        # ----------------------------------------------------------------
        SummaryReporter(config).print(findings)

        # ----------------------------------------------------------------
        # Open report(s) in the default viewer if --open was passed
        # ----------------------------------------------------------------
        if config.open_report:
            for path in written_paths:
                open_file(path)

    except SystemExit:
        raise   # let controlled exits (validate, preflight, guard) propagate cleanly

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠  Scan interrupted by user.[/yellow]")
        raise SystemExit(130)   # 130 = script terminated by Ctrl-C (POSIX convention)

    except Exception as e:
        logger.critical(f"Unexpected error during scan: {e}")
        # Show a full traceback in verbose mode so the developer can debug
        if config and config.verbose:
            console.print_exception(show_locals=False)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
