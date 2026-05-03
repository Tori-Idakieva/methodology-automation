"""
utils/logger.py — Centralised logging configuration.

All modules obtain their logger via get_logger(__name__) so that log
format, level, and handlers are controlled from a single place.

Uses Rich's RichHandler so that log output renders cleanly alongside
progress bars and spinners without interleaving.

Supported levels (lowest to highest severity):
  debug    — fine-grained detail, payload injection steps, raw responses
  info     — general progress messages (default)
  warning  — unexpected but recoverable situations
  error    — a check or request failed, scan continues
  critical — fatal error, scanner cannot continue
"""

import logging
from rich.logging import RichHandler
from utils.console import console

_configured = False

# Map string names (from CLI) to logging constants
LOG_LEVELS = {
    "debug":    logging.DEBUG,
    "info":     logging.INFO,
    "warning":  logging.WARNING,
    "error":    logging.ERROR,
    "critical": logging.CRITICAL,
}


def configure_logging(level: int = logging.INFO) -> None:
    """
    Set up the root logger with a RichHandler on the shared console.

    Called automatically by get_logger() on first import, and again by
    configure_from_config() once CLI args are available.
    """
    global _configured
    if _configured:
        return

    handler = RichHandler(
        console=console,        # use the shared console instance
        show_path=False,        # don't show file:line for every message
        rich_tracebacks=False,  # keep tracebacks plain for readability
        markup=False,           # log messages are plain text, not markup
        log_time_format="[%H:%M:%S]",
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)
    _configured = True


def configure_from_config(log_level: str = "info", verbose: bool = False) -> None:
    """
    Call once from main.py to apply the user's chosen log level.

    --verbose overrides --log-level and forces DEBUG output.
    Always updates the root logger level regardless of import order so
    that modules imported before main() don't lock in the default level.
    """
    level = logging.DEBUG if verbose else LOG_LEVELS.get(log_level.lower(), logging.INFO)
    configure_logging(level)
    logging.getLogger().setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, initialising the root handler if needed."""
    configure_logging()
    return logging.getLogger(name)
