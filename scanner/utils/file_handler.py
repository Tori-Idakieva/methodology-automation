"""
utils/file_handler.py — File I/O helpers.

Provides safe write wrappers and evidence directory management
(e.g., creating the folder where screenshots get saved).
"""

import os
import json
import webbrowser
from typing import Any
from utils.logger import get_logger

logger = get_logger(__name__)

EVIDENCE_DIR = "evidence"


def ensure_evidence_dir() -> str:
    """
    Create the evidence/ directory if it does not exist.

    Returns the path to the directory.
    """
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    return EVIDENCE_DIR


def write_json(path: str, data: Any, indent: int = 2) -> None:
    """
    Write `data` as JSON to `path`, creating parent directories if needed.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent)
    logger.debug(f"Wrote JSON to {path}")


def save_html(path: str, content: str) -> None:
    """
    Write an HTML string to `path`, creating parent directories if needed.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    logger.debug(f"Wrote HTML report to {path}")


def open_file(path: str) -> None:
    """
    Open `path` in the user's default application.

    HTML files open in the default web browser; JSON files open in whatever
    application the OS has registered for .json (browser, text editor, etc.).

    Uses Python's built-in webbrowser module — no extra dependencies needed
    and works on Linux, macOS, and Windows.
    """
    abs_path = os.path.abspath(path)
    url = f"file://{abs_path}"
    logger.info(f"Opening report: {url}")
    webbrowser.open(url)


def screenshot_path(label: str) -> str:
    """Return a full path for a screenshot file inside the evidence dir."""
    ensure_evidence_dir()
    safe_label = label.replace("/", "_").replace(":", "")
    return os.path.join(EVIDENCE_DIR, f"{safe_label}.png")
