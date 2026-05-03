"""
utils/http.py — Shared HTTP session factory.

Provides a single function for building a pre-configured requests.Session
so crawlers and detectors don't each repeat the same setup block.
"""

import requests
from config import ScannerConfig
from utils.logger import get_logger

logger = get_logger(__name__)


def build_session(config: ScannerConfig) -> requests.Session:
    """
    Create a requests.Session pre-configured with the scanner's default
    headers and auth cookie (if one was provided via --auth-cookie).

    Centralising this avoids duplicating the same three-step setup
    (Session → headers → cookie) across every module that makes HTTP requests.

    Args:
        config: The active ScannerConfig instance.

    Returns:
        A fully configured requests.Session ready for use.
    """
    session = requests.Session()
    session.headers.update(config.default_headers)

    if config.auth_cookie:
        name, _, value = config.auth_cookie.partition("=")
        session.cookies.set(name.strip(), value.strip())
        logger.debug(f"Auth cookie applied to session: {name.strip()}")

    return session
