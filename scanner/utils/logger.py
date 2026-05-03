"""
utils/logger.py — Centralised logging configuration.

All modules obtain their logger via get_logger(__name__) so that log
format, level, and handlers are controlled from a single place.
"""

import logging
import sys

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_configured = False


def configure_logging(level: int = logging.INFO) -> None:
    """
    Set up the root logger. Call once from main.py before any other imports.
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


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, ensuring the root is configured."""
    configure_logging()
    return logging.getLogger(name)
