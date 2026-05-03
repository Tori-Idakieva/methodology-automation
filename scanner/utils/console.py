"""
utils/console.py — Shared Rich Console instance.

A single Console is used by both the logger (via RichHandler) and main.py
(for phase banners and progress displays). Using one instance ensures that
live spinners, progress bars, and log output all render on the same stream
without interleaving.
"""

from rich.console import Console

console = Console()
