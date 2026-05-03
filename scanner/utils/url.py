"""
utils/url.py — Shared URL utility functions.

Centralises URL normalisation, scope checking, origin extraction, and
query-parameter injection so the two crawlers and the XSS / SQLi detectors
don't each carry identical implementations.
"""

from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)


def normalise_url(base_url: str, href: str) -> Optional[str]:
    """
    Resolve `href` against `base_url`, strip URL fragments, and validate
    the scheme.

    Args:
        base_url: The page URL used to resolve relative hrefs.
        href:     The raw href value extracted from an anchor or form.

    Returns:
        The normalised absolute URL string, or None if the scheme is not
        http or https (e.g. mailto:, javascript:, data:).
    """
    try:
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https"):
            return None

        # Strip fragment (#section) — fragments are client-side only and
        # would cause the same page to be crawled multiple times
        clean = parsed._replace(fragment="")
        return urlunparse(clean)

    except Exception as e:
        logger.debug(f"Could not normalise URL '{href}': {e}")
        return None


def in_scope(url: str, target: str) -> bool:
    """
    Return True if `url` belongs to the same domain (netloc) as `target`.

    Prevents the crawler from following links to third-party domains.
    """
    return urlparse(url).netloc == urlparse(target).netloc


def origin(url: str) -> str:
    """
    Return the scheme + host of `url` (e.g. 'http://localhost:8080').

    Used to deduplicate checks that only need to run once per server,
    such as security header inspection.
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def inject_param(url: str, param: str, payload: str) -> str:
    """
    Return a copy of `url` with the query parameter `param` set to `payload`.
    All other query parameters retain their original values.

    Used by XSS and SQLi detectors to build injection URLs one parameter
    at a time, so vulnerable parameters can be identified precisely.

    Args:
        url:     The original URL containing query parameters.
        param:   The query parameter name to replace.
        payload: The injection string to set as the parameter value.

    Returns:
        The modified URL with `param` set to `payload`.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
