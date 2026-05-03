"""
detectors/ — Vulnerability detection modules.

Each detector follows the same interface:
    detector.run(urls: List[str]) -> List[dict]

Findings dicts contain at minimum:
    {
        "type":        str,   # e.g. "XSS", "SQLi"
        "url":         str,
        "severity":    str,   # "High" | "Medium" | "Low" | "Info"
        "detail":      str,
        "evidence":    str,   # payload / response snippet / screenshot path
    }
"""
