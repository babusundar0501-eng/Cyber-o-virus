"""Reversible, user-directed quarantine for NO.1.

This module never executes files and never permanently deletes them.
Quarantine is an MVP: same-filesystem atomic moves only; no symlink following.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path

from platform_support import app_data_dir

CHUNK_SIZE = 1024 * 1024
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(stat.S_IRWXU)


def quarantine_file(source: str | Path, quarantine_dir: str | Path | None = None) -> Path:
    """Move a regular file into quarantine and write a hash-verified restore record."""
    original = Path(source).expanduser()
    if original.is_symlink():
        raise ValueError("Refusing to quarantine a symbolic link")
    if not original.exists() or not original.is_file():
        raise ValueError("Only an existing regular file can be quarantined")
    resolved = original.resolve(strict=True)
    digest = sha256_file(resolved)
    folder = Path(quarantine_dir) if quarantine_dir else app_data_dir() / "Quarantine"
    _secure_dir(folder)
    token = uuid.uuid4().hex
    stored = folder / f"{token}.quarantined"
    metadata = folder / f"{token}.json"

    # os.replace is atomic on one filesystem. Fail rather than silently copy.
    os.replace(resolved, stored)
    try:
        record = {
            "schema_version": 1,
            "original_path": str(resolved),
            "stored_name": stored.name,
            "sha256": digest,
        }
        metadata.write_text(json.dumps(record, indent=2), encoding="utf-8")
        if os.name == "posix":
            metadata.chmod(stat.S_IRUSR | stat.S_IWUSR)
        if sha256_file(stored) != digest:
            raise OSError("Quarantined file hash verification failed")
    except Exception:
        # Best-effort rollback only when the original path is still unused.
        if not resolved.exists() and stored.exists():
            os.replace(stored, resolved)
        metadata.unlink(missing_ok=True)
        raise
    return metadata


def restore_file(record_path: str | Path) -> Path:
    """Restore only a valid record whose stored file still matches its SHA-256."""
    record_file = Path(record_path)
    if record_file.is_symlink() or not record_file.is_file():
        raise ValueError("Restore record is missing or is not a regular file")
    folder = record_file.parent.resolve()
    data = json.loads(record_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Unsupported quarantine record")
    stored_name = data.get("stored_name")
    digest = data.get("sha256")
    original_text = data.get("original_path")
    if (not isinstance(stored_name, str) or Path(stored_name).name != stored_name
            or not isinstance(digest, str) or not HASH_RE.fullmatch(digest)
            or not isinstance(original_text, str)):
        raise ValueError("Invalid quarantine record")
    stored = folder / stored_name
    original = Path(original_text)
    if not original.is_absolute():
        raise ValueError("Restore destination must be an absolute path")
    if stored.is_symlink() or not stored.is_file():
        raise ValueError("Quarantined file is missing or is not a regular file")
    if sha256_file(stored) != digest:
        raise ValueError("Quarantined file hash changed; refusing restore")
    if original.exists() or original.is_symlink():
        raise FileExistsError(f"Restore destination already exists: {original}")
    original.parent.mkdir(parents=True, exist_ok=True)
    os.replace(stored, original)
    if sha256_file(original) != digest:
        raise OSError("Restored file hash verification failed")
    record_file.unlink(missing_ok=True)
    return original
