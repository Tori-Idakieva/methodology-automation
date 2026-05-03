"""
reporting/ — Output and reporting modules.

Reporters consume a list of finding dicts produced by detectors and
render them in the requested format (JSON file, styled HTML, terminal summary).

Shared helpers defined here are imported by all reporter classes to avoid
duplicating the same logic across three separate files.
"""

from typing import List

# Canonical severity ordering used for sorting findings consistently across
# all output formats (High → Medium → Low → Info)
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def severity_counts(findings: List[dict]) -> dict:
    """
    Return a {severity: count} dict tallied across all findings.

    Unknown severity values fall into their own bucket rather than
    silently inflating an existing one.
    """
    counts: dict = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
