"""NO.1's transparent, local detection-family checks.

These are small specialized checks, not separate commercial antivirus products.
They never execute scanned files and can produce false positives.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

RISKY_EXTENSIONS = {
    ".scr", ".pif", ".com", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd", ".lnk",
}
DOUBLE_EXTENSIONS = (
    ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".png.exe",
    ".txt.exe", ".xlsx.exe", ".mp4.exe", ".jpeg.exe", ".gif.exe",
)
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".hta", ".wsf"}
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SCRIPT_PATTERNS = (
    (re.compile(rb"powershell(?:\\.exe)?[^\\r\\n]{0,160}-(?:enc|encodedcommand)\\b", re.I),
     "Script contains an encoded PowerShell command pattern"),
    (re.compile(rb"frombase64string\\s*\\(", re.I),
     "Script contains a Base64-decoding pattern"),
)

ENGINE_INFO = {
    "DAD": ("Dad Engine", "Executable and disguised-file names"),
    "MOM": ("Mom Engine", "Suspicious script patterns"),
    "UNCLE": ("Uncle Engine", "Local SHA-256 and filename indicators"),
    "SON": ("Son Engine", "Harmless EICAR test signature"),
    "AUNT": ("Aunt Engine", "Risky extension combinations"),
}


def run_file_type_engine(path: Path) -> list[str]:
    if path.suffix.lower() in RISKY_EXTENSIONS:
        return [f"[DAD] Executable/script type: {path.suffix}"]
    return []


def run_script_engine(path: Path, sample: bytes) -> list[str]:
    if path.suffix.lower() not in SCRIPT_EXTENSIONS:
        return []
    return [f"[MOM] {description}" for pattern, description in SCRIPT_PATTERNS if pattern.search(sample)]


def run_ioc_engine(path: Path, file_hash: str, match_indicators) -> tuple[list[str], list[str]]:
    matches, warnings = match_indicators(path, file_hash)
    return [f"[UNCLE] {item}" for item in matches], warnings


def run_test_signature_engine(found: bool) -> list[str]:
    return ["[SON] EICAR antivirus test string detected (harmless test pattern)"] if found else []


def run_disguise_engine(path: Path) -> list[str]:
    name = path.name.lower()
    if any(name.endswith(ext) for ext in DOUBLE_EXTENSIONS):
        return ["[AUNT] Double extension may disguise an executable"]
    return []


def run_family_engines(path: Path, sample: bytes, eicar_found: bool, file_hash: str, match_indicators) -> tuple[list[str], list[str]]:
    """Run all local family checks and return findings plus rule-validation warnings."""
    findings: list[str] = []
    findings.extend(run_file_type_engine(path))
    findings.extend(run_disguise_engine(path))
    findings.extend(run_script_engine(path, sample))
    findings.extend(run_test_signature_engine(eicar_found))
    ioc_matches, warnings = run_ioc_engine(path, file_hash, match_indicators)
    findings.extend(ioc_matches)
    return findings, warnings
