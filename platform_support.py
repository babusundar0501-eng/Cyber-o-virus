"""Cross-platform information for NO.1's ClamAV-powered desktop scanner."""
from __future__ import annotations

import platform
import sys
from pathlib import Path


def platform_name() -> str:
    if sys.platform.startswith("win"):
        return "Windows"
    if sys.platform == "darwin":
        return "macOS"
    if sys.platform.startswith("linux"):
        return "Linux"
    return platform.system() or sys.platform


def app_data_dir() -> Path:
    """Return a per-user data directory without requiring third-party packages."""
    name = platform_name()
    home = Path.home()
    if name == "Windows":
        base = Path.home() / "AppData" / "Local"
    elif name == "macOS":
        base = home / "Library" / "Application Support"
    else:
        base = Path.home() / ".local" / "share"
    return base / "NO1-AntiVirus"


def capability_summary() -> dict[str, str]:
    """Describe what this prototype can safely claim on the current OS."""
    return {
        "platform": platform_name(),
        "engine": "ClamAV command-line scanner (clamscan)",
        "external_antivirus": "ClamAV is the scanning engine",
        "real_time_protection": "Polling folder monitor only; not full system protection",
        "privileged_monitoring": "Not implemented",
    }
