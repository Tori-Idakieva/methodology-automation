"""
utils/file_handler.py — File I/O helpers.

Provides safe read/write wrappers and evidence directory management
(e.g., creating the folder where screenshots get saved).
"""

import os
import json
from typing import Any
from utils.logger import get_logger

logger = get_logger(__name__)

EVIDENCE_DIR = "evidence"


def create_output_dir(path: str) -> str:
    """
    Create an output directory at `path` if it does not already exist.

    Returns the path to the directory.
    """
    os.makedirs(path, exist_ok=True)
    logger.debug(f"Output directory ready: {path}")
    return path


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


def read_json(path: str) -> Any:
    """Read and return JSON content from `path`."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_html(path: str, content: str) -> None:
    """
    Write an HTML string to `path`, creating parent directories if needed.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    logger.debug(f"Wrote HTML report to {path}")


def save_text_summary(path: str, content: str) -> None:
    """
    Write a plain-text summary to `path`, creating parent directories if needed.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    logger.debug(f"Wrote text summary to {path}")


def screenshot_path(label: str) -> str:
    """Return a full path for a screenshot file inside the evidence dir."""
    ensure_evidence_dir()
    safe_label = label.replace("/", "_").replace(":", "")
    return os.path.join(EVIDENCE_DIR, f"{safe_label}.png")
