"""ClamAV process integration for NO.1. No fallback or simulated scan results."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def find_clamscan() -> str | None:
    """Find ClamAV's scanner executable. Never silently fall back to fake detection."""
    found = shutil.which("clamscan")
    if found:
        return found
    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV" / "clamscan.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "ClamAV" / "clamscan.exe",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
    return None


def scan_with_clamav(targets: list[Path], recursive: bool = True) -> tuple[int, list[str], str]:
    """Run ClamAV; exit codes are 0=clean, 1=infected, 2=error."""
    executable = find_clamscan()
    if not executable:
        return 2, [], "ClamAV was not found. Install ClamAV and put clamscan on PATH."
    existing = [str(path) for path in targets if path.exists()]
    missing = [str(path) for path in targets if not path.exists()]
    if not existing:
        return 2, [], "No selected scan locations exist: " + ", ".join(missing)
    command = [executable, "--infected", "--no-summary", "--max-filesize=1G", "--max-scansize=4G"]
    if recursive:
        command.append("--recursive")
    for pattern in (r"^/proc($|/)", r"^/sys($|/)", r"^/dev($|/)", r"^/run($|/)",
                    r"^/System/Volumes/Preboot($|/)", r"^/System/Volumes/VM($|/)"):
        command.append("--exclude-dir=" + pattern)
    command.extend(existing)
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", check=False)
    except OSError as exc:
        return 2, [], f"Could not start ClamAV: {exc}"
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    infected = [line for line in lines if line.upper().endswith("FOUND")]
    errors = [line for line in lines if "ERROR" in line.upper() or "ACCESS DENIED" in line.upper()]
    diagnostic = "\n".join(errors[:30])
    if missing:
        diagnostic = (diagnostic + "\n" if diagnostic else "") + "Missing locations: " + ", ".join(missing)
    return result.returncode, infected, diagnostic


def inspect_file(path: Path) -> tuple[str, list[str], str]:
    """Inspect a single file using the ClamAV engine."""
    if path.is_symlink():
        return "SKIPPED", ["Symbolic links are not followed"], ""
    if not path.exists() or not path.is_file():
        return "ERROR", ["File does not exist or is not a regular file"], ""
    code, infected, diagnostic = scan_with_clamav([path], recursive=False)
    if code == 0:
        return "NO MATCH*", [], ""
    if code == 1:
        return "WARNING", infected or ["ClamAV reported an infected file"], ""
    return "ERROR", [diagnostic or "ClamAV could not complete the scan"], ""
