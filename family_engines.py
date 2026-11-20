"""NO.1's independent static detection checks.

These transparent heuristics inspect bytes and names only. They never execute files.
A match is a reason to review a file, not proof of malware.
"""
from __future__ import annotations

import re
from pathlib import Path

DOUBLE_EXTENSIONS = (
    ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".png.exe",
    ".txt.exe", ".xlsx.exe", ".mp4.exe", ".jpeg.exe", ".gif.exe",
    ".pdf.scr", ".jpg.scr", ".png.scr", ".txt.scr",
)
DOCUMENT_MEDIA_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".mp3", ".wav",
    ".mp4", ".mov", ".avi", ".txt", ".rtf", ".csv",
}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".hta", ".wsf", ".py", ".sh"}
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Each rule is intentionally narrow and reports the evidence it matched.
SCRIPT_PATTERNS = (
    (re.compile(rb"powershell(?:\.exe)?[^\r\n]{0,160}-(?:enc|encodedcommand)\b", re.I),
     "Encoded PowerShell command option found"),
    (re.compile(rb"frombase64string\s*\(", re.I),
     "PowerShell Base64-decoding function found"),
    (re.compile(rb"\b(?:eval|exec)\s*\(\s*(?:atob|base64|decode)", re.I),
     "Dynamic execution combined with encoded/decode content found"),
    (re.compile(rb"(?:curl|wget|invoke-webrequest|urlopen)[^\r\n]{0,240}(?:\|\s*(?:sh|bash)|\b(?:iex|invoke-expression)\b)", re.I),
     "Remote download appears directly chained to command execution"),
)

ENGINE_INFO = {
    "DAD": ("DAD / File structure", "Detects executable content disguised as documents"),
    "MOM": ("MOM / Script analysis", "Checks selected suspicious script behaviours"),
    "UNCLE": ("UNCLE / Local intelligence", "Matches locally configured SHA-256 and filename indicators"),
    "SON": ("SON / Test signature", "Detects the harmless EICAR test string"),
    "AUNT": ("AUNT / Disguise checks", "Checks suspicious double file extensions"),
}


def _executable_format(sample: bytes) -> str | None:
    if sample.startswith(b"MZ"):
        return "Windows PE-style executable (MZ)"
    if sample.startswith(b"\\x7fELF"):
        return "ELF executable"
    if sample.startswith((b"\\xfe\\xed\\xfa\\xce", b"\\xfe\\xed\\xfa\\xcf",
                          b"\\xce\\xfa\\xed\\xfe", b"\\xcf\\xfa\\xed\\xfe",
                          b"\\xca\\xfe\\xba\\xbe")):
        return "Mach-O or universal binary"
    return None


def run_file_type_engine(path: Path, sample: bytes) -> list[str]:
    file_format = _executable_format(sample)
    if file_format and path.suffix.lower() in DOCUMENT_MEDIA_EXTENSIONS:
        return [f"[DAD] {file_format} content has a document/media extension ({path.suffix})"]
    return []


def run_executable_disguise_engine(path: Path, sample: bytes) -> list[str]:
    # Kept as a separate compatibility check for the existing engine dashboard.
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
    name = path.name.casefold()
    if any(name.endswith(ext) for ext in DOUBLE_EXTENSIONS):
        return ["[AUNT] Double extension may disguise executable content"]
    return []


def run_family_engines(path: Path, sample: bytes, eicar_found: bool, file_hash: str, match_indicators) -> tuple[list[str], list[str]]:
    findings: list[str] = []
    findings.extend(run_file_type_engine(path, sample))
    findings.extend(run_executable_disguise_engine(path, sample))
    findings.extend(run_disguise_engine(path))
    findings.extend(run_script_engine(path, sample))
    findings.extend(run_test_signature_engine(eicar_found))
    ioc_matches, warnings = run_ioc_engine(path, file_hash, match_indicators)
    findings.extend(ioc_matches)
    return findings, warnings
