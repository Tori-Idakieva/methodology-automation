"""
utils/logger.py — Centralised logging configuration.

All modules obtain their logger via get_logger(__name__) so that log
format, level, and handlers are controlled from a single place.

Supported levels (lowest to highest severity):
  debug    — fine-grained detail, payload injection steps, raw responses
  info     — general progress messages (default)
  warning  — unexpected but recoverable situations
  error    — a check or request failed, scan continues
  critical — fatal error, scanner cannot continue
"""

import logging
import sys

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
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
    Set up the root logger with a stdout handler and timestamp format.
    Called automatically by get_logger() and configure_from_config().
    """
    global _configured
    if _configured:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)
    _configured = True


def configure_from_config(log_level: str = "info", verbose: bool = False) -> None:
    """
    Call once from main.py to set log level based on CLI args.

    --verbose overrides --log-level and forces DEBUG.
    Always updates the root logger level regardless of import order.
    """
    if verbose:
        level = logging.DEBUG
    else:
        level = LOG_LEVELS.get(log_level.lower(), logging.INFO)

    configure_logging(level)
    logging.getLogger().setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, ensuring the root is configured."""
    configure_logging()
    return logging.getLogger(name)
